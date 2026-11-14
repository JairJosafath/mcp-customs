package checker

import (
	"errors"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/aws/aws-durable-execution-sdk-go/durable/durabletest"

	"github.com/JairJosafath/mcp-customs/src/internal/poller"
	"github.com/JairJosafath/mcp-customs/src/internal/store"
	"github.com/JairJosafath/mcp-customs/src/internal/verdict"
)

// reviewedRecheck is a world whose approved check c0 is kept and whose
// judge fails, so code gives the re-check review and it waits for a person.
func reviewedRecheck() *world {
	w := newWorld(cleanServer())
	w.rec.checks = []store.Check{{ID: "c0", Submission: npm, Status: store.StatusDone, Verdict: "pass"}}
	w.judge = &recordedJudge{probes: "probes_weather"}
	return w
}

func TestARecheckSupersedesTheApprovedCheckBeforeItWaitsForAPerson(t *testing.T) {
	w := reviewedRecheck()
	runner := durabletest.NewLocalRunner(Handler(w.deps()))
	if _, err := runner.RunUntilComplete(newVersion(false)); err != nil {
		t.Fatal(err)
	}
	if len(runner.OpenCallbacks()) != 1 {
		t.Fatalf("open callbacks %+v, want the re-check waiting for a person", runner.OpenCallbacks())
	}
	if c0, _, _ := w.rec.GetCheck(t.Context(), "c0"); c0.SupersededBy != "recheck-1" {
		t.Errorf("approved check %+v while the re-check waits, want it superseded already", c0)
	}
	if len(w.events.superseded) != 1 || w.events.superseded[0].Verdict != string(verdict.Review) {
		t.Errorf("events %+v while the re-check waits, want one superseded event with code's review", w.events.superseded)
	}
}

func TestAPersonsApprovalLiftsTheSupersededMarkAndSaysSo(t *testing.T) {
	w := reviewedRecheck()
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
	out, err := durabletest.ResultAs[Output](result)
	if err != nil || out.Verdict != verdict.Pass {
		t.Fatalf("output %+v, %v; want a pass a person approved", out, err)
	}
	if c0, _, _ := w.rec.GetCheck(t.Context(), "c0"); c0.SupersededBy != "" {
		t.Errorf("approved check %+v, want the mark lifted", c0)
	}
	if len(w.events.superseded) != 1 || len(w.events.lifted) != 1 {
		t.Fatalf("events superseded %+v, lifted %+v; want one of each", w.events.superseded, w.events.lifted)
	}
	if got := w.events.lifted[0]; got.ApprovedCheckID != "c0" || got.RecheckID != "recheck-1" || got.Verdict != string(verdict.Pass) {
		t.Errorf("lifted event %+v, want c0 lifted by recheck-1's pass", got)
	}
}

func TestAPersonsBlockKeepsTheMarkAndSendsNoSecondEvent(t *testing.T) {
	w := reviewedRecheck()
	runner := durabletest.NewLocalRunner(Handler(w.deps()))
	in := newVersion(false)
	if _, err := runner.RunUntilComplete(in); err != nil {
		t.Fatal(err)
	}
	if err := runner.SendCallbackSuccess(runner.OpenCallbacks()[0].CallbackID, HumanAnswer{Decision: DecisionBlock}); err != nil {
		t.Fatal(err)
	}
	if _, err := runner.RunUntilComplete(in); err != nil {
		t.Fatal(err)
	}
	if c0, _, _ := w.rec.GetCheck(t.Context(), "c0"); c0.SupersededBy != "recheck-1" || len(w.events.superseded) != 1 || len(w.events.lifted) != 0 {
		t.Errorf("approved check %+v, events %+v, lifted %+v; want it superseded once", c0, w.events.superseded, w.events.lifted)
	}
}

func TestOnlyTheNewestPolledVersionsRecheckSupersedesWhicheverEndsLast(t *testing.T) {
	recheckOf := func(version string) Input {
		return Input{
			CheckID: "recheck-" + strings.ReplaceAll(version, ".", "-"), Submission: store.Submission{Kind: "npm", Ref: "weather-mcp@" + version},
			Recheck: &Recheck{CheckID: "c0", Ref: "weather-mcp@1.0.0", ToolListHash: "t"},
		}
	}
	for _, order := range [][]string{{"1.0.1", "1.0.2"}, {"1.0.2", "1.0.1"}} {
		w := reviewedRecheck()
		w.rec.newestPolled = "1.0.2"
		for _, v := range order {
			runCheck(t, w, recheckOf(v))
		}
		if c0, _, _ := w.rec.GetCheck(t.Context(), "c0"); c0.SupersededBy != "recheck-1-0-2" {
			t.Errorf("order %v: approved check %+v, want it superseded by 1.0.2's re-check", order, c0)
		}
		if len(w.events.superseded) != 1 || w.events.superseded[0].RecheckID != "recheck-1-0-2" {
			t.Errorf("order %v: events %+v, want one, for 1.0.2's re-check", order, w.events.superseded)
		}
	}
}

func TestARetryThatPassesLiftsTheMarkTheFailedRecheckLeft(t *testing.T) {
	// The reviewer's repro: code says review, so c0 is marked; a person
	// approves; writing the verdict fails, so the re-check fails and asks
	// for its retry; the retry passes and must lift recheck-1's mark.
	w := reviewedRecheck()
	w.rec.newestPolled = "1.0.1"
	w.reports.reportErr = errors.New("the bucket is unavailable")
	first := newVersion(false)
	first.CheckID = poller.RecheckID("npm", "weather-mcp", "1.0.1")
	runner := durabletest.NewLocalRunner(Handler(w.deps()))
	if _, err := runner.RunUntilComplete(first); err != nil {
		t.Fatal(err)
	}
	if err := runner.SendCallbackSuccess(runner.OpenCallbacks()[0].CallbackID, HumanAnswer{Decision: DecisionApprove}); err != nil {
		t.Fatal(err)
	}
	result, err := runner.RunUntilComplete(first)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != durabletest.Failed || len(w.rec.retries) != 1 {
		t.Fatalf("status %s, retries %v; want the re-check failed and its retry asked", result.Status, w.rec.retries)
	}
	if c0, _, _ := w.rec.GetCheck(t.Context(), "c0"); c0.SupersededBy != first.CheckID {
		t.Fatalf("approved check %+v, want it still superseded by the failed re-check", c0)
	}

	// The poller starts the retry; this time it passes by code.
	w.reports.reportErr = nil
	w.judge = cleanJudge()
	retry := newVersion(true)
	retry.CheckID = poller.RetryID("npm", "weather-mcp", "1.0.1")
	if out := runCheck(t, w, retry); out.Verdict != verdict.Pass {
		t.Fatalf("retry verdict %s, want pass", out.Verdict)
	}
	if c0, _, _ := w.rec.GetCheck(t.Context(), "c0"); c0.SupersededBy != "" {
		t.Errorf("approved check %+v, want the failed re-check's mark lifted by its retry", c0)
	}
	if len(w.events.lifted) != 1 || w.events.lifted[0].RecheckID != retry.CheckID {
		t.Errorf("lifted events %+v, want one, from the retry", w.events.lifted)
	}
}

func TestARecheckAtReviewThatCantSupersedeFailsAndIsRetried(t *testing.T) {
	srv := cleanServer()
	srv.fail = map[string]int{"/install": http.StatusUnprocessableEntity}
	w := newWorld(srv)
	w.rec.checks = []store.Check{{ID: "c0", Submission: npm, Status: store.StatusDone, Verdict: "pass"}}
	w.rec.supersedeErr = errors.New("throttled")
	runFailing(t, w, newVersion(false))
	if !slices.Equal(w.rec.retries, []string{"npm#weather-mcp@1.0.1"}) {
		t.Errorf("retries asked %v, want one: the approved check still stands", w.rec.retries)
	}
}
