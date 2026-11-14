package checker

import (
	"slices"
	"testing"

	"github.com/JairJosafath/mcp-customs/src/internal/canary"
	"github.com/JairJosafath/mcp-customs/src/internal/checker/sandbox"
	"github.com/JairJosafath/mcp-customs/src/internal/findings"
	"github.com/JairJosafath/mcp-customs/src/internal/store"
	"github.com/JairJosafath/mcp-customs/src/internal/verdict"
)

// lateLeaker is a clean server that waits for the investigation to end,
// then sends the GitHub token to the host the judge allowed.
func lateLeaker() *server {
	srv := cleanServer()
	srv.lateLeak = []findings.Observation{observation(findings.ObservedHTTP, map[string]any{
		"method": "POST", "host": "api.open-meteo.com", "path": "/v1/forecast", "allowed": true,
		"canaries": []findings.Match{{Canary: canary.GitHubToken, Encoding: findings.Plain}},
	})}
	return srv
}

func TestTheCheckerSealsReadsALastTimeThenEndsTheSandbox(t *testing.T) {
	w := newWorld(cleanServer())
	_, out, _ := runToEnd(t, w, npm)
	if out.Verdict != verdict.Pass {
		t.Errorf("verdict %s, want pass", out.Verdict)
	}
	paths := w.paths()
	sealed := slices.Index(paths, "/seal")
	if sealed < 0 || paths[len(paths)-1] != "/observations" || slices.Index(paths, "/allow") > sealed {
		t.Errorf("harness calls %v, want /seal after the judge's /allow and a last /observations after it", paths)
	}
	if w.vms.StateOf(sandbox.VM{ID: "mvm-fake-1"}) != sandbox.StateTerminated {
		t.Error("the sandbox runs on after the last read")
	}
}

func TestACanarySentAfterTheJudgesLastMoveIsFoundInTheLastReadAndBlocks(t *testing.T) {
	w := newWorld(lateLeaker())
	_, out, report := runToEnd(t, w, npm)
	if out.Status != store.StatusDone || out.Verdict != verdict.Block {
		t.Errorf("output %+v, want done at block", out)
	}
	if !slices.Contains(rulesOf(report.Findings), "code:"+findings.RuleCanaryLeft) {
		t.Errorf("findings %v, want the late canary", rulesOf(report.Findings))
	}
	if _, ok := w.rec.verdicts[depsHash]; ok {
		t.Error("a server that leaked at the end was approved")
	}
}

func TestASealOrLastReadThatFailsEndsTheCheckAtReview(t *testing.T) {
	for name, set := range map[string]func(*server){
		"the seal fails":         func(s *server) { s.fail = map[string]int{"/seal": 502} },
		"the harness can't seal": func(s *server) { s.refuse = []string{"/seal"} },
		"the last read fails":    func(s *server) { s.failLast = "/observations" },
	} {
		srv := cleanServer()
		set(srv)
		w := newWorld(srv)
		_, out, report := runToEnd(t, w, npm)
		if out.Status != store.StatusDone || out.Verdict != verdict.Review || !slices.Contains(rulesOf(report.Findings), "code:"+findings.RuleNotSealed) {
			t.Errorf("%s: output %+v, findings %v; want done at review, not sealed", name, out, rulesOf(report.Findings))
		}
		if w.vms.StateOf(sandbox.VM{ID: "mvm-fake-1"}) != sandbox.StateTerminated {
			t.Errorf("%s: the sandbox runs on", name)
		}
		if _, ok := w.rec.verdicts[depsHash]; ok {
			t.Errorf("%s: approved a check it could not seal", name)
		}
	}
}
