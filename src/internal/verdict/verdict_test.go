package verdict

import (
	"errors"
	"slices"
	"testing"

	"github.com/JairJosafath/mcp-customs/src/internal/findings"
)

func code(rule string) findings.Finding {
	return findings.Finding{Source: findings.Code, Rule: rule, Evidence: "e"}
}

func model(rule string) findings.Finding {
	return findings.Finding{Source: findings.Model, Rule: rule, Evidence: "e"}
}

func TestDecide(t *testing.T) {
	errJudge := errors.New("bedrock: throttled")
	tests := []struct {
		name string
		in   Input
		want Verdict
	}{
		{"nothing found and model pass", Input{ModelVerdict: Pass}, Pass},
		{"model review raises pass", Input{ModelVerdict: Review}, Review},
		{"model block raises pass", Input{ModelVerdict: Block}, Block},
		{"model finding raises pass to review", Input{Model: []findings.Finding{model("purpose-mismatch")}, ModelVerdict: Pass}, Review},
		{"canary left, model pass", Input{Code: []findings.Finding{code(findings.RuleCanaryLeft)}, ModelVerdict: Pass}, Block},
		{"canary left, model review", Input{Code: []findings.Finding{code(findings.RuleCanaryLeft)}, ModelVerdict: Review}, Block},
		{"agent config write, model pass", Input{Code: []findings.Finding{code(findings.RuleAgentConfig)}, ModelVerdict: Pass}, Block},
		{"shell startup write, model pass", Input{Code: []findings.Finding{code(findings.RuleShellStartup)}, ModelVerdict: Pass}, Block},
		{"unexplained sampling, model pass", Input{Code: []findings.Finding{code(findings.RuleSampling)}, ModelVerdict: Pass}, Review},
		{"TLS the proxy couldn't read, model pass", Input{Code: []findings.Finding{code(findings.RuleTLSNotIntercepted)}, ModelVerdict: Pass}, Review},
		{"a body the proxy couldn't search, model pass", Input{Code: []findings.Finding{code(findings.RuleBodyUnscanned)}, ModelVerdict: Pass}, Review},
		{"direct traffic not all recorded, model pass", Input{Code: []findings.Finding{code(findings.RuleDirectUnrecorded)}, ModelVerdict: Pass}, Review},
		{"unexplained elicitation, model pass", Input{Code: []findings.Finding{code(findings.RuleElicitation)}, ModelVerdict: Pass}, Review},
		{"variation selector, model pass", Input{Code: []findings.Finding{code(findings.RuleVariationSelector)}, ModelVerdict: Pass}, Review},
		{"ANSI escape, model pass", Input{Code: []findings.Finding{code(findings.RuleANSIEscape)}, ModelVerdict: Pass}, Review},
		{"tag characters, model pass", Input{Code: []findings.Finding{code(findings.RuleTagCharacters)}, ModelVerdict: Pass}, Review},
		{"zero-width, model pass", Input{Code: []findings.Finding{code(findings.RuleZeroWidth)}, ModelVerdict: Pass}, Review},
		{"bidi control, model pass", Input{Code: []findings.Finding{code(findings.RuleBidiControl)}, ModelVerdict: Pass}, Review},
		{"injection pattern, model pass", Input{Code: []findings.Finding{code(findings.RuleSecretResend)}, ModelVerdict: Pass}, Review},
		{"hidden characters, model block", Input{Code: []findings.Finding{code(findings.RuleZeroWidth)}, ModelVerdict: Block}, Block},
		{"unknown code rule gives review", Input{Code: []findings.Finding{code("something-new")}, ModelVerdict: Pass}, Review},
		{"judge error gives review", Input{JudgeErr: errJudge}, Review},
		{"judge error ignores a stale model pass", Input{JudgeErr: errJudge, ModelVerdict: Pass}, Review},
		{"judge error keeps a code block", Input{Code: []findings.Finding{code(findings.RuleCanaryLeft)}, JudgeErr: errJudge}, Block},
		{"out of turns gives review", Input{OutOfTurns: true, ModelVerdict: Pass}, Review},
		{"judge error keeps the judge's earlier block", Input{JudgeErr: errJudge, ModelVerdict: Block}, Block},
		{"out of turns keeps the judge's earlier block", Input{OutOfTurns: true, ModelVerdict: Block}, Block},
		{"missing model verdict gives review", Input{}, Review},
		{"unknown model verdict gives review", Input{ModelVerdict: "approve"}, Review},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Decide(tt.in).Verdict; got != tt.want {
				t.Errorf("Decide(%+v) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestDecideReturnsEveryFindingWithItsSource(t *testing.T) {
	disguised := findings.Finding{Source: findings.Code, Rule: "looks-fine", Evidence: "trust me"}
	got := Decide(Input{
		Code:       []findings.Finding{{Rule: findings.RuleCanaryLeft, Evidence: "github-token, base64"}},
		Model:      []findings.Finding{disguised},
		OutOfTurns: true,
	}).Findings
	want := []findings.Finding{
		{Source: findings.Code, Rule: findings.RuleCanaryLeft, Evidence: "github-token, base64"},
		{Source: findings.Code, Rule: findings.RuleJudgeOutOfTurn, Evidence: "the investigation ran out of turns, so a person must review"},
		{Source: findings.Model, Rule: "looks-fine", Evidence: "trust me"},
	}
	if !slices.Equal(got, want) {
		t.Errorf("Findings = %+v, want %+v", got, want)
	}
}

func TestDecideAddsJudgeErrorFinding(t *testing.T) {
	got := Decide(Input{JudgeErr: errors.New("timeout")}).Findings
	want := []findings.Finding{{Source: findings.Code, Rule: findings.RuleJudgeError, Evidence: "the judge failed, so a person must review"}}
	if !slices.Equal(got, want) {
		t.Errorf("Findings = %+v, want %+v", got, want)
	}
}

func TestDecideLetsOnlyAPersonClearACodeFloor(t *testing.T) {
	canaryLeft := []findings.Finding{code(findings.RuleCanaryLeft)}
	for name, tc := range map[string]struct {
		in   Input
		want Verdict
	}{
		"a person approves a canary leaving":  {Input{Code: canaryLeft, ModelVerdict: Pass, Human: HumanApprove}, Pass},
		"a person blocks a clean server":      {Input{ModelVerdict: Pass, Human: HumanBlock}, Block},
		"a person approves after a judge err": {Input{JudgeErr: errors.New("x"), Human: HumanApprove}, Pass},
		"no decision keeps the floor":         {Input{Code: canaryLeft, ModelVerdict: Pass, Human: "maybe"}, Block},
		"the model's pass clears nothing":     {Input{Code: canaryLeft, ModelVerdict: Pass}, Block},
	} {
		got := Decide(tc.in)
		if got.Verdict != tc.want {
			t.Errorf("%s: %s, want %s", name, got.Verdict, tc.want)
		}
		if len(got.Findings) < len(tc.in.Code) {
			t.Errorf("%s: dropped findings: %+v", name, got.Findings)
		}
	}
}
