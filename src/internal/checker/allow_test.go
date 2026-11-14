package checker

import (
	"slices"
	"testing"

	"github.com/JairJosafath/mcp-customs/src/internal/findings"
	"github.com/JairJosafath/mcp-customs/src/internal/store"
	"github.com/JairJosafath/mcp-customs/src/internal/verdict"
)

func TestAnAllowlistReachingTheStacksOwnAPIIsRefusedRecordedAndEndsAtReview(t *testing.T) {
	for name, set := range map[string]func(*recordedJudge){
		// The judge read the server's text and was persuaded to expect a
		// name that resolves to the stack's API.
		"a name resolving to it": func(j *recordedJudge) { j.judgement = "judgement_own_api" },
		"the API host itself": func(j *recordedJudge) {
			j.judgeAnswer = &Judgement{Verdict: verdict.Pass, ExpectedHosts: []string{"api.open-meteo.com", apiHost}}
		},
	} {
		w := newWorld(cleanServer())
		set(w.judge)
		result, out, report := runToEnd(t, w, npm)
		if slices.Contains(w.paths(), "/allow") {
			t.Errorf("%s: harness calls %v, want no /allow", name, w.paths())
		}
		i := slices.IndexFunc(w.rec.steps, func(s store.Step) bool { return s.Name == string(ActAllow) })
		if i < 0 || !slices.ContainsFunc(w.rec.steps[i].Findings, func(f store.Finding) bool { return f.Rule == findings.RuleOwnAPIHost }) {
			t.Errorf("%s: steps %v, want the allow step to record the refusal", name, w.rec.stepNames())
		}
		if _, _, moves := w.judge.calls(); moves != 0 || slices.Contains(w.rec.stepNames(), "investigate") {
			t.Errorf("%s: %d move(s), steps %v; want no investigation", name, moves, w.rec.stepNames())
		}
		if result.Operation("own-api") == nil {
			t.Errorf("%s: no own-api step:\n%s", name, result.FormatTree())
		}
		if out.Verdict != verdict.Review || !slices.Contains(rulesOf(report.Findings), "code:"+findings.RuleOwnAPIHost) {
			t.Errorf("%s: verdict %s, findings %v; want review with %s", name, out.Verdict, rulesOf(report.Findings), findings.RuleOwnAPIHost)
		}
		if !slices.Contains(w.paths(), "/seal") {
			t.Errorf("%s: harness calls %v, want the sandbox still sealed", name, w.paths())
		}
	}
}
