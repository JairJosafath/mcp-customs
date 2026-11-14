package checker

import (
	"net/http"
	"reflect"
	"testing"

	"github.com/aws/aws-durable-execution-sdk-go/durable/durabletest"

	"github.com/JairJosafath/mcp-customs/src/internal/checker/sandbox"
	"github.com/JairJosafath/mcp-customs/src/internal/findings"
	"github.com/JairJosafath/mcp-customs/src/internal/store"
	"github.com/JairJosafath/mcp-customs/src/internal/verdict"
)

func TestAServerTheSandboxCantInstallEndsAtReviewDecidedByCode(t *testing.T) {
	srv := cleanServer()
	srv.fail = map[string]int{"/install": http.StatusUnprocessableEntity}
	w := newWorld(srv)
	result, err := durabletest.NewLocalRunner(Handler(w.deps())).RunUntilComplete(Input{CheckID: "c1", Submission: npm})
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
	want := []findings.Finding{{Source: findings.Code, Rule: findings.RuleInstallFailed, Evidence: "the server failed /install"}}
	if !ok || report.DecidedBy != "code" || !reflect.DeepEqual(report.Findings, want) {
		t.Errorf("report %+v, want decided by code with %+v", report, want)
	}
	if got := w.rec.stepNames(); !reflect.DeepEqual(got, []string{"start", "resolve", "verdict"}) {
		t.Errorf("steps %v, want start, resolve and verdict: nothing to ask a person", got)
	}
	if got := w.paths(); !reflect.DeepEqual(got, []string{"/install"}) {
		t.Errorf("called %v, want /install alone", got)
	}
	if got := w.vms.StateOf(sandbox.VM{ID: "mvm-fake-1"}); got != sandbox.StateTerminated {
		t.Errorf("the sandbox is %s, want terminated", got)
	}
	if len(w.rec.verdicts) != 0 {
		t.Errorf("approvals %v, want none", w.rec.verdicts)
	}
}
