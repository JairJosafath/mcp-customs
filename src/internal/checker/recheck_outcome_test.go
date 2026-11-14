package checker

import (
	"bytes"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/aws/aws-durable-execution-sdk-go/durable"
	"github.com/aws/aws-durable-execution-sdk-go/durable/durabletest"

	"github.com/JairJosafath/mcp-customs/src/internal/events"
	"github.com/JairJosafath/mcp-customs/src/internal/store"
	"github.com/JairJosafath/mcp-customs/src/internal/verdict"
)

// failingRecheck is a world whose approved check c0 is kept, and whose
// server's install fails, so a re-check of it fails.
func failingRecheck() *world {
	srv := cleanServer()
	srv.fail = map[string]int{"/install": 502}
	w := newWorld(srv)
	w.rec.checks = []store.Check{{ID: "c0", Submission: npm, Status: store.StatusDone, Verdict: "pass"}}
	return w
}

// runFailing runs in on w until it fails, logging to the answered buffer.
func runFailing(t *testing.T, w *world, in Input) *bytes.Buffer {
	t.Helper()
	logs := &bytes.Buffer{}
	runner := durabletest.NewLocalRunner(Handler(w.deps()), durable.WithLogHandler(slog.NewJSONHandler(logs, nil)))
	result, err := runner.RunUntilComplete(in)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != durabletest.Failed {
		t.Fatalf("status %s, want failed", result.Status)
	}
	return logs
}

func newVersion(retry bool) Input {
	return Input{
		CheckID: "recheck-1", Submission: store.Submission{Kind: "npm", Ref: "weather-mcp@1.0.1"},
		Recheck: &Recheck{CheckID: "c0", Ref: "weather-mcp@1.0.0", ToolListHash: "t", Retry: retry},
	}
}

func lastStep(w *world) store.Step { return w.rec.steps[len(w.rec.steps)-1] }

func TestARecheckThatFailsAsksThePollerToStartItOnceMore(t *testing.T) {
	w := failingRecheck()
	logs := runFailing(t, w, newVersion(false))
	if !slices.Equal(w.rec.retries, []string{"npm#weather-mcp@1.0.1"}) {
		t.Errorf("retries asked %v, want one of weather-mcp@1.0.1", w.rec.retries)
	}
	if step := lastStep(w); step.Name != "retry" || !strings.Contains(step.Summary, "started once more") {
		t.Errorf("last step %+v, want the retry said", step)
	}
	if c0, _, _ := w.rec.GetCheck(t.Context(), "c0"); c0.RecheckFailed != "" || c0.SupersededBy != "" {
		t.Errorf("approved check %+v, want it untouched by a first failure", c0)
	}
	if strings.Contains(logs.String(), FailedTwiceKey) {
		t.Errorf("logs %s, want no alarm on a first failure", logs)
	}
}

func TestARecheckOvertakenByANewerVersionIsNotRetried(t *testing.T) {
	w := failingRecheck()
	w.rec.overtaken = true
	runFailing(t, w, newVersion(false))
	if step := lastStep(w); step.Name != "retry" || !strings.Contains(step.Summary, "not started again") {
		t.Errorf("last step %+v, want it said the newer version is re-checked instead", step)
	}
}

func TestARetryThatFailsIsRecordedOnTheApprovedCheckAndRaisesTheAlarm(t *testing.T) {
	w := failingRecheck()
	in := newVersion(true)
	in.CheckID = "recheck-1-retry"
	logs := runFailing(t, w, in)
	if len(w.rec.retries) != 0 {
		t.Errorf("retries asked %v, want none: a retry is never retried", w.rec.retries)
	}
	if c0, _, _ := w.rec.GetCheck(t.Context(), "c0"); c0.RecheckFailed != "recheck-1-retry" {
		t.Errorf("approved check %+v, want the failed retry recorded on it", c0)
	}
	if step := lastStep(w); step.Name != "recheck-failed" {
		t.Errorf("last step %+v, want the second failure said", step)
	}
	// The stack's metric filter counts this entry: its alarm goes off.
	if n := strings.Count(logs.String(), `"`+FailedTwiceKey+`":1`); n != 1 || !strings.Contains(logs.String(), FailedTwiceLog) {
		t.Errorf("logs %s, want one %q entry with %s 1", logs, FailedTwiceLog, FailedTwiceKey)
	}
}

func TestARecheckThatDoesNotPassSupersedesTheApprovedCheckAndSaysSo(t *testing.T) {
	w := newWorld(cleanServer())
	w.rec.checks = []store.Check{{ID: "c0", Submission: npm, Status: store.StatusDone, Verdict: "pass"}}
	// A judge that fails gives review.
	w.judge = &recordedJudge{probes: "probes_weather"}
	in := newVersion(false)
	out := runCheck(t, w, in)
	if out.Verdict != verdict.Review {
		t.Fatalf("verdict %s, want review", out.Verdict)
	}
	if c0, _, _ := w.rec.GetCheck(t.Context(), "c0"); c0.SupersededBy != "recheck-1" {
		t.Errorf("approved check %+v, want it superseded by recheck-1", c0)
	}
	want := []events.Superseded{{
		ApprovedCheckID: "c0", ApprovedRef: "weather-mcp@1.0.0", RecheckID: "recheck-1",
		Kind: "npm", Ref: "weather-mcp@1.0.1", Verdict: string(out.Verdict),
	}}
	if !slices.Equal(w.events.superseded, want) {
		t.Errorf("events %+v, want %+v", w.events.superseded, want)
	}
}

func TestARecheckThatPassesOrAFreshCheckSupersedesNothing(t *testing.T) {
	for name, in := range map[string]Input{
		"a re-check that passes": newVersion(false),
		"a fresh check":          {CheckID: "c1", Submission: npm},
	} {
		w := newWorld(cleanServer())
		w.rec.checks = []store.Check{{ID: "c0", Submission: npm, Status: store.StatusDone, Verdict: "pass"}}
		if out := runCheck(t, w, in); out.Verdict != verdict.Pass {
			t.Fatalf("%s: verdict %s, want pass", name, out.Verdict)
		}
		if c0, _, _ := w.rec.GetCheck(t.Context(), "c0"); c0.SupersededBy != "" || len(w.events.superseded) != 0 {
			t.Errorf("%s: approved check %+v, events %+v; want nothing superseded", name, c0, w.events.superseded)
		}
	}
}

func TestTheStacksMetricFiltersCountTheKeysTheCheckerLogs(t *testing.T) {
	stack, err := os.ReadFile(filepath.Join("..", "..", "..", "infra", "recheck_outcomes.ts"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"FAILED_TWICE_KEY = '" + FailedTwiceKey + "'", "LIFT_FAILED_KEY = '" + LiftFailedKey + "'"} {
		if !strings.Contains(string(stack), want) {
			t.Errorf("infra/recheck_outcomes.ts lacks %q: the alarm would never see the log entry", want)
		}
	}
}
