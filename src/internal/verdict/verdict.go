// Package verdict decides pass, review or block from code and model
// findings. Code findings set a floor no model finding can lower; the model
// can only make the verdict stricter; a judge that fails or runs out of
// turns gives at least review; only a person's decision is final.
package verdict

import "github.com/JairJosafath/mcp-customs/src/internal/findings"

// Verdict is the outcome of a check.
type Verdict string

// The three verdicts, from least to most strict.
const (
	Pass   Verdict = "pass"
	Review Verdict = "review"
	Block  Verdict = "block"
)

var strictness = map[Verdict]int{Pass: 0, Review: 1, Block: 2}

// codeFloors is the least strict verdict each code rule allows. A code rule
// missing here gives review.
var codeFloors = map[string]Verdict{
	findings.RuleCanaryLeft:        Block,
	findings.RuleAgentConfig:       Block,
	findings.RuleShellStartup:      Block,
	findings.RuleTLSNotIntercepted: Review,
	findings.RuleBodyUnscanned:     Review,
	findings.RuleDirectUnrecorded:  Review,
	findings.RuleSampling:          Review,
	findings.RuleElicitation:       Review,
	findings.RuleANSIEscape:        Review,
	findings.RuleTagCharacters:     Review,
	findings.RuleZeroWidth:         Review,
	findings.RuleBidiControl:       Review,
	findings.RuleVariationSelector: Review,
	findings.RuleInstruction:       Review,
	findings.RuleSensitivePath:     Review,
	findings.RuleSecretResend:      Review,
	findings.RuleJudgeError:        Review,
	findings.RuleJudgeOutOfTurn:    Review,
	findings.RuleUnprobedTool:      Review,
	findings.RuleOversized:         Review,
	findings.RuleNotSealed:         Review,
}

// Input is what a verdict is decided from.
type Input struct {
	// Code are the findings code made.
	Code []findings.Finding
	// Model are the findings the judge made; each gives at least review.
	Model []findings.Finding
	// ModelVerdict is the judge's own verdict, the strictest it gave.
	// Anything but pass, review or block gives review. It counts even when
	// the judge later failed or ran out of turns.
	ModelVerdict Verdict
	// JudgeErr is the judge's failure, if it failed.
	JudgeErr error
	// OutOfTurns says the judge's investigation ran out of turns.
	OutOfTurns bool
	// Human is a person's decision, HumanApprove or HumanBlock, once code
	// asked for one; anything else is no decision. A person alone may clear
	// a code floor.
	Human string
}

// The decisions a person may give.
const (
	HumanApprove = "approve"
	HumanBlock   = "block"
)

// Result is a verdict and every finding behind it.
type Result struct {
	Verdict  Verdict            `json:"verdict"`
	Findings []findings.Finding `json:"findings"`
}

// Decide returns the verdict for in. Each finding's source is set by the
// list it came in, so a model finding can't pass itself off as code.
func Decide(in Input) Result {
	code := append([]findings.Finding{}, in.Code...)
	if in.JudgeErr != nil {
		code = append(code, findings.Finding{Rule: findings.RuleJudgeError, Evidence: "the judge failed, so a person must review"})
	}
	if in.OutOfTurns {
		code = append(code, findings.Finding{Rule: findings.RuleJudgeOutOfTurn, Evidence: "the investigation ran out of turns, so a person must review"})
	}
	verdict := Pass
	all := make([]findings.Finding, 0, len(code)+len(in.Model))
	for _, f := range code {
		f.Source = findings.Code
		verdict = stricter(verdict, codeFloor(f.Rule))
		all = append(all, f)
	}
	for _, f := range in.Model {
		f.Source = findings.Model
		verdict = stricter(verdict, Review)
		all = append(all, f)
	}
	// A verdict the judge gave before it failed or ran out of turns still
	// counts: it can only make the verdict stricter, and the failure's own
	// finding already gives review.
	verdict = stricter(verdict, modelVerdict(in.ModelVerdict))
	switch in.Human {
	case HumanApprove:
		verdict = Pass
	case HumanBlock:
		verdict = Block
	}
	return Result{Verdict: verdict, Findings: all}
}

func codeFloor(rule string) Verdict {
	if v, ok := codeFloors[rule]; ok {
		return v
	}
	return Review
}

func modelVerdict(v Verdict) Verdict {
	if _, ok := strictness[v]; ok {
		return v
	}
	return Review
}

func stricter(a, b Verdict) Verdict {
	if strictness[b] > strictness[a] {
		return b
	}
	return a
}
