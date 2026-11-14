package checker

import (
	"errors"
	"testing"

	"github.com/aws/aws-durable-execution-sdk-go/durable/durabletest"

	"github.com/JairJosafath/mcp-customs/src/internal/store"
)

// approvalsOnlyOfDoneChecks fails t when a HASH# or APPROVED item names a
// check that is not done: a later check of that dependency set would pass
// as seen before on the approval of a check that failed.
func approvalsOnlyOfDoneChecks(t *testing.T, w *world) {
	t.Helper()
	named := []string{}
	for _, v := range w.rec.verdicts {
		named = append(named, v.CheckID)
	}
	for _, a := range w.rec.approved {
		named = append(named, a.CheckID)
	}
	for _, id := range named {
		if c, _, _ := w.rec.GetCheck(t.Context(), id); c.Status != store.StatusDone {
			t.Errorf("an approval names check %s, which is %q, not done", id, c.Status)
		}
	}
}

// approvedRecheck runs a re-check a person approves after code did not
// pass it, so its pass lifts the approved check's superseded mark.
func approvedRecheck(t *testing.T, w *world) *durabletest.TestResult {
	t.Helper()
	runner := durabletest.NewLocalRunner(Handler(w.deps()))
	in := newVersion(false)
	if _, err := runner.RunUntilComplete(in); err != nil {
		t.Fatal(err)
	}
	if err := runner.SendCallbackSuccess(runner.OpenCallbacks()[0].CallbackID, HumanAnswer{Decision: DecisionApprove}); err != nil {
		t.Fatal(err)
	}
	result, err := runner.RunUntilComplete(in)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func TestAPassThatCantLiftOrAnnounceStaysDoneWithItsApproval(t *testing.T) {
	for name, outage := range map[string]func(*world){
		"lifting the mark fails":    func(w *world) { w.rec.liftErr = errors.New("throttled") },
		"announcing the lift fails": func(w *world) { w.events.liftedErr = errors.New("eventbridge down") },
	} {
		t.Run(name, func(t *testing.T) {
			w := reviewedRecheck()
			outage(w)
			result := approvedRecheck(t, w)
			if result.Status != durabletest.Succeeded {
				t.Errorf("status %s, error %+v; want the pass kept", result.Status, result.Error)
			}
			check, _, _ := w.rec.GetCheck(t.Context(), "recheck-1")
			if check.Status != store.StatusDone || check.Verdict != "pass" || len(w.rec.verdicts) != 1 {
				t.Errorf("check %+v, HASH# %+v; want done with its pass and approval", check, w.rec.verdicts)
			}
			approvalsOnlyOfDoneChecks(t, w)
		})
	}
}

func TestAPassCommittedButAnsweredAsFailedStaysDone(t *testing.T) {
	w := newWorld(cleanServer())
	w.rec.lostPassReply = errors.New("connection reset")
	result, err := durabletest.NewLocalRunner(Handler(w.deps())).RunUntilComplete(Input{CheckID: "c1", Submission: npm})
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != durabletest.Failed {
		t.Errorf("status %s, want the execution failed after its retries", result.Status)
	}
	if check := w.rec.checks[0]; check.Status != store.StatusDone {
		t.Errorf("check %+v; want it left done, as its pass committed", check)
	}
	approvalsOnlyOfDoneChecks(t, w)
}
