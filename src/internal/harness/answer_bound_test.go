package harness

import (
	"slices"
	"strings"
	"testing"

	"github.com/JairJosafath/mcp-customs/src/internal/findings"
)

// An answer cut after a flood filled every cap is still recorded, with
// what the scans of the whole found: they are nowhere else.
func TestACutAnswerIsRecordedPastEveryCap(t *testing.T) {
	run := newTestRun(t, &fakeInstaller{})
	name := strings.Repeat("a", 2000)
	for range maxPerKind + 1 {
		for _, k := range []ObservationKind{ObservedDNS, ObservedConnect, ObservedHTTP, ObservedFile, ObservedHook} {
			run.h.obs.add(k, map[string]any{"name": name})
		}
	}
	// The last bytes under the cap on every kind together.
	for range 100 {
		run.h.obs.add(findings.ObservedProcess, map[string]any{})
	}
	small := map[string]string{"text": "Sunny."}
	if got := run.h.bounded("the result of tools/call", small, maxCallResult); !isSame(got, small) {
		t.Errorf("a result within the bound became %v", got)
	}
	cut := run.h.bounded("the result of tools/call", map[string]string{"text": strings.Repeat("<", maxCallResult) + worstInjection}, maxCallResult)
	if c, ok := cut.(CutValue); !ok || !c.Cut || len(c.Excerpt) > maxCutExcerpt || c.SHA256 == "" {
		t.Errorf("a result over the bound became %+v, want a CutValue", cut)
	}
	got := decided(t, run.h.obs.all(), nil)
	var rules []string
	for _, f := range got.Findings {
		rules = append(rules, f.Rule)
	}
	if !slices.Contains(rules, findings.RuleOversized) || !slices.Contains(rules, findings.RuleInstruction) {
		t.Errorf("findings %v, want %s and %s", rules, findings.RuleOversized, findings.RuleInstruction)
	}
}

func isSame(got any, want map[string]string) bool {
	m, ok := got.(map[string]string)
	return ok && m["text"] == want["text"]
}
