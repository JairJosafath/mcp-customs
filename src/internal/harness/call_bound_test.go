package harness

import (
	"encoding/json"
	"net/http"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/JairJosafath/mcp-customs/src/internal/findings"
	"github.com/JairJosafath/mcp-customs/src/internal/verdict"
)

// probeStep is the most a step of the Checker keeps (checker.maxStepResult).
const probeStep = 200 << 10

// cutAnswer is the CutValue an answer holds in place of field.
func cutAnswer(t *testing.T, body map[string]json.RawMessage, field string) CutValue {
	t.Helper()
	var c CutValue
	if err := json.Unmarshal(body[field], &c); err != nil || !c.Cut {
		t.Fatalf("%s is %.200s, want it cut: %v", field, body[field], err)
	}
	return c
}

// observedNow is the verdict code gives the run's observations so far, the
// model at pass, and the oversized observations among them.
func observedNow(t *testing.T, run testRun) (verdict.Result, []findings.Observation) {
	t.Helper()
	_, got := run.do(t, http.MethodGet, "/observations", nil)
	var obs []findings.Observation
	must(t, json.Unmarshal(got["observations"], &obs))
	var cuts []findings.Observation
	for _, o := range obs {
		if o.Kind == findings.ObservedOversized {
			cuts = append(cuts, o)
		}
	}
	return verdict.Decide(verdict.Input{Code: findings.FromObservations(obs, canaryList(testCanaries)), ModelVerdict: verdict.Pass}), cuts
}

func rulesOf(r verdict.Result) []string {
	var rules []string
	for _, f := range r.Findings {
		rules = append(rules, f.Rule)
	}
	return rules
}

// A tool's result over the cut but under the finding bound, as real file
// readers and searches answer, is cut to fit a step and passes; the cut is
// on the report. One past the finding bound is oversized. An injection
// past the cut is found in the whole result at any size.
func TestALargeToolResultIsCutAndOnlyAFindingPastItsBound(t *testing.T) {
	tests := []struct {
		name      string
		size      int
		body      string
		want      verdict.Verdict
		wantRules []string
	}{
		{"a clean 1 MiB result", 1 << 20, "", verdict.Pass, nil},
		{"a clean result past the finding bound", maxResultFinding + 1, "", verdict.Review, []string{findings.RuleOversized}},
		{"an injection past the cut of a 1 MiB result", 1 << 20, worstInjection, verdict.Review, []string{findings.RuleInstruction}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			run := startTestServer(t)
			if status, body := run.do(t, http.MethodPost, "/start", map[string]any{}); status != http.StatusOK {
				t.Fatalf("POST /start = %d %v", status, body)
			}
			c := cutAnswer(t, call(t, run, "big", map[string]any{"size": tt.size, "body": tt.body}), "result")
			if c.Bytes < tt.size || len(c.Excerpt) > maxCutExcerpt {
				t.Errorf("cut to %d bytes with a %d-byte excerpt, want the whole result's size and an excerpt", c.Bytes, len(c.Excerpt))
			}
			got, cuts := observedNow(t, run)
			if got.Verdict != tt.want || !slices.Equal(rulesOf(got), tt.wantRules) {
				t.Errorf("verdict %s with findings %v, want %s with %v", got.Verdict, rulesOf(got), tt.want, tt.wantRules)
			}
			if len(cuts) != 1 || !strings.Contains(string(cuts[0].Detail), c.SHA256) {
				t.Errorf("oversized observations %v, want the cut's, with its SHA-256 %s", cuts, c.SHA256)
			}
		})
	}
}

// The same holds for the initialize result: a large one is cut only, as
// the judge never reads it and every scan runs on the whole.
func TestALargeInitializeResultIsCutOnly(t *testing.T) {
	exe, err := os.Executable()
	must(t, err)
	run := newTestRun(t, &fakeInstaller{out: Installed{Resolved: []byte("mod test\n"), Command: []string{exe, testServerArg, strconv.Itoa(1 << 20)}}})
	if status, body := run.do(t, http.MethodPost, "/install", installBody("go", "example.com/weather@v1.0.0")); status != http.StatusOK {
		t.Fatalf("POST /install = %d %v", status, body)
	}
	status, body := run.do(t, http.MethodPost, "/start", map[string]any{})
	if status != http.StatusOK {
		t.Fatalf("POST /start = %d %v", status, body)
	}
	cutAnswer(t, body, "initialize")
	if got, cuts := observedNow(t, run); got.Verdict != verdict.Pass || len(cuts) != 1 {
		t.Errorf("verdict %s with findings %v and %d cuts, want pass with the cut on the report", got.Verdict, rulesOf(got), len(cuts))
	}
}

// A tool's error of bytes that aren't UTF-8, under the cut as the server
// sent it, is cut as the Checker would encode it, so the probe that keeps
// it as a string still fits its step.
func TestAnErrorThatIsNotUTF8IsCutAsTheCheckerEncodesIt(t *testing.T) {
	run := startTestServer(t)
	if status, body := run.do(t, http.MethodPost, "/start", map[string]any{}); status != http.StatusOK {
		t.Fatalf("POST /start = %d %v", status, body)
	}
	body := call(t, run, "bad_error", map[string]any{"size": 60_000})
	// What the probe step keeps: the error, as a string.
	failed, err := json.Marshal(string(body["error"]))
	must(t, err)
	if len(failed) > probeStep {
		t.Errorf("the probe would keep a %d-byte error, over the %d a step keeps", len(failed), probeStep)
	}
	cutAnswer(t, body, "error")
}
