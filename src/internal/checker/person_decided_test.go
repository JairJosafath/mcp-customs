package checker

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/JairJosafath/mcp-customs/src/internal/store"
)

func TestAPersonsBlockWhoseVerdictCantBeWrittenIsNeverRetried(t *testing.T) {
	// The review's repro: a person blocks, and every write of the done
	// verdict fails. A retry would start from nothing and could approve
	// the version the person blocked.
	w := reviewedRecheck()
	w.rec.doneErr = errors.New("throttled")
	_, logs := decidedRecheck(t, w, DecisionBlock)
	if len(w.rec.retries) != 0 {
		t.Fatalf("retries asked %v, want none: a person blocked the re-check", w.rec.retries)
	}
	if c0, _, _ := w.rec.GetCheck(t.Context(), "c0"); c0.SupersededBy != "recheck-1" || c0.RecheckFailed != "recheck-1" {
		t.Errorf("approved check %+v, want it still superseded, and marked as left undecided", c0)
	}
	if len(w.rec.approved) != 0 || len(w.events.lifted) != 0 {
		t.Errorf("approvals %+v, lifted %+v; want the block standing", w.rec.approved, w.events.lifted)
	}
	if !strings.Contains(logs.String(), PersonsVerdictLostLog) || !strings.Contains(logs.String(), `"`+FailedTwiceKey+`":1`) {
		t.Errorf("logs %s, want a %q entry with %s 1", logs, PersonsVerdictLostLog, FailedTwiceKey)
	}
}

func TestAPersonsBlockWhoseVerdictStepFailedIsWrittenAgain(t *testing.T) {
	// The verdict's page step can't be written, so the verdict step never
	// ran: the person's block is written again instead of a retry asked.
	w := reviewedRecheck()
	w.rec.failStep = "verdict"
	decidedRecheck(t, w, DecisionBlock)
	if len(w.rec.retries) != 0 {
		t.Errorf("retries asked %v, want none: a person blocked the re-check", w.rec.retries)
	}
	if check, _, _ := w.rec.GetCheck(t.Context(), "recheck-1"); check.Status != store.StatusDone || check.Verdict != "block" {
		t.Errorf("re-check %+v, want it done with the person's block", check)
	}
	if c0, _, _ := w.rec.GetCheck(t.Context(), "c0"); c0.SupersededBy != "recheck-1" || c0.RecheckFailed != "" {
		t.Errorf("approved check %+v, want it superseded, and not marked", c0)
	}
}

func TestAPersonsVerdictStandsWhenTheAskHumanStepCantBeWritten(t *testing.T) {
	// The review's repro: the ask_human page step fails after the person
	// answered. The check must not be left waiting with the answer dropped.
	for decision, want := range map[string]string{DecisionApprove: "pass", DecisionBlock: "block"} {
		t.Run(decision, func(t *testing.T) {
			w := reviewedRecheck()
			w.rec.failStep = "ask_human"
			decidedRecheck(t, w, decision)
			if check, _, _ := w.rec.GetCheck(t.Context(), "recheck-1"); check.Status != store.StatusDone || check.Verdict != want {
				t.Errorf("re-check %+v, want it done with the person's %s", check, want)
			}
			if len(w.rec.retries) != 0 {
				t.Errorf("retries asked %v, want none", w.rec.retries)
			}
			c0, _, _ := w.rec.GetCheck(t.Context(), "c0")
			if lifted := c0.SupersededBy == ""; lifted != (decision == DecisionApprove) {
				t.Errorf("approved check %+v, want the mark lifted only on an approve", c0)
			}
		})
	}
}

func TestAPersonsDecisionWithNoReportIsNoSuspend(t *testing.T) {
	// A person decided but no report was made: fail must close the check
	// and raise the alarm, not pass the error on as the SDK suspending.
	if isSuspend(errNoReport) || isSuspend(fmt.Errorf("wrapped: %w", errNoReport)) || isSuspend(ErrNoTime) {
		t.Error("isSuspend reads the Checker's own errors as the SDK suspending")
	}
}

func TestAPersonsVerdictWrittenAgainIsDoneEvenWhenRecordingTheFailureFails(t *testing.T) {
	// Review round 2, finding 2: once the person's verdict is written
	// again, the check is done; a FailCheck that fails must not mark the
	// approved check as left undecided, nor skip the lift.
	w := reviewedRecheck()
	// The verdict step's six attempts (the SDK's default) fail; the
	// re-write, the seventh, succeeds.
	w.rec.doneErr, w.rec.doneFails = errors.New("throttled"), 6
	w.rec.failErr = errors.New("throttled")
	_, logs := decidedRecheck(t, w, DecisionApprove)
	if check, _, _ := w.rec.GetCheck(t.Context(), "recheck-1"); check.Status != store.StatusDone || check.Verdict != "pass" {
		t.Errorf("re-check %+v, want it done with the person's pass", check)
	}
	if c0, _, _ := w.rec.GetCheck(t.Context(), "c0"); c0.SupersededBy != "" || c0.RecheckFailed != "" {
		t.Errorf("approved check %+v, want the mark lifted and no recheckFailed", c0)
	}
	if strings.Contains(logs.String(), PersonsVerdictLostLog) {
		t.Errorf("logs %s, want no %q entry", logs, PersonsVerdictLostLog)
	}
}

func TestAPersonsVerdictWrittenAgainGetsItsPageStep(t *testing.T) {
	// Review round 2, finding 4: the verdict's page step failed, so after
	// the verdict is written again the page must still say who decided.
	w := reviewedRecheck()
	w.rec.failStep, w.rec.failStepUntilDone = "verdict", true
	decidedRecheck(t, w, DecisionBlock)
	if step := lastStep(w); step.Name != "verdict" || !strings.Contains(step.Summary, "decided by a person blocked") {
		t.Errorf("last step %+v, want the person's verdict on the page", step)
	}
}
