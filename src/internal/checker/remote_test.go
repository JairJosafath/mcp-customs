package checker

import (
	"reflect"
	"testing"

	"github.com/aws/aws-durable-execution-sdk-go/durable/durabletest"

	"github.com/JairJosafath/mcp-customs/src/internal/findings"
	"github.com/JairJosafath/mcp-customs/src/internal/store"
	"github.com/JairJosafath/mcp-customs/src/internal/verdict"
)

func TestARemoteServerEndsAtReviewDecidedByCodeWithoutASandbox(t *testing.T) {
	w := newWorld(cleanServer())
	remote := store.Submission{Kind: "remote", Ref: "https://example.com/mcp"}
	result, err := durabletest.NewLocalRunner(Handler(w.deps())).RunUntilComplete(Input{CheckID: "c1", Submission: remote})
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != durabletest.Succeeded {
		t.Fatalf("status %s, error %+v; want a verdict", result.Status, result.Error)
	}
	if check := w.rec.checks[0]; check.Status != store.StatusDone || check.Verdict != string(verdict.Review) {
		t.Errorf("check %+v, want done at review", check)
	}
	report, ok := w.reports.report()
	want := []findings.Finding{remoteUnsupported(remote.Ref)}
	if !ok || report.DecidedBy != "code" || report.Verdict != verdict.Review || !reflect.DeepEqual(report.Findings, want) {
		t.Errorf("report %+v, want review decided by code with %+v", report, want)
	}
	if got := want[0]; got.Source != findings.Code || got.Rule != findings.RuleRemoteUnsupported || got.Evidence == "" {
		t.Errorf("finding %+v, want a code finding of %s that says why", got, findings.RuleRemoteUnsupported)
	}
	if got := w.rec.stepNames(); !reflect.DeepEqual(got, []string{"start", "resolve", "verdict"}) {
		t.Errorf("steps %v, want start, resolve and verdict: nothing to ask a person", got)
	}
	if n := w.vms.Launched(); n != 0 {
		t.Errorf("launched %d sandbox(es), want none", n)
	}
	if got := w.paths(); len(got) != 0 {
		t.Errorf("called %v, want nothing", got)
	}
	if len(w.rec.verdicts) != 0 {
		t.Errorf("approvals %v, want none", w.rec.verdicts)
	}
}
