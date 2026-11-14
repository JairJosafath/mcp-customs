package checker

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/aws/aws-durable-execution-sdk-go/durable"

	"github.com/JairJosafath/mcp-customs/src/internal/findings"
)

// maxStepResult bounds what a step may return: under the 256 KB the SDK
// can checkpoint, with room for the SDK's own envelope. A step whose
// answer is larger keeps the whole answer in the bucket and returns only
// its size, so a padded tool list, result or flood of observations ends
// the check as failed instead of breaking its checkpoints.
const maxStepResult = 200 << 10

// ErrTooLarge says an answer of the server was larger than a step can
// keep; the check fails, and its failed step says so.
var ErrTooLarge = errors.New("an answer of the server is larger than a step can keep")

// sizeOf is the size of v as a step's result.
func sizeOf(v any) int {
	b, err := json.Marshal(v)
	if err != nil {
		return 0
	}
	return len(b)
}

// keepOversized puts raw, an answer too large for a step, in the bucket as
// observations/<check-id>-<what>.json.
func (r *run) keepOversized(sc durable.StepContext, what string, raw any) error {
	b, err := json.Marshal(raw)
	if err != nil {
		return fmt.Errorf("encode the oversized %s: %w", what, err)
	}
	return r.deps.Reports.PutOversized(sc, r.in.CheckID, what, b)
}

// tooLarge records that the answer called what was size bytes, and answers
// ErrTooLarge for the action to fail with.
func (r *run) tooLarge(what string, size int) error {
	r.oversized = &findings.Finding{
		Source: findings.Code, Rule: findings.RuleOversized,
		Evidence: fmt.Sprintf("%s was %d KB, over the %d KB a step can keep; it is in observations/%s-%s.json",
			what, size>>10, maxStepResult>>10, r.in.CheckID, what),
	}
	return ErrTooLarge
}

// What a STEP# item keeps of its findings: under DynamoDB's 400 KB an item
// may hold, however many findings the server's text and actions make. The
// verdict is decided from every finding, and the report keeps them all;
// only the step's record of them is cut.
const (
	maxFindingsPerRule = 20
	maxStepFindings    = 200
	maxEvidence        = 512
	maxRule            = 64
)

// ruleMore names the finding that counts the findings a step left off
// because it already kept as many as it may. It is a record, not a rule:
// no verdict is decided from it.
const ruleMore = "more-findings"

// boundFindings is fs as a step keeps them: the first maxFindingsPerRule of
// each rule, at most maxStepFindings in all, each rule and evidence cut to
// its bound, and one finding per rule counting those left off.
func boundFindings(fs []findings.Finding) []findings.Finding {
	kept := make([]findings.Finding, 0, min(len(fs), maxStepFindings))
	var rules []findings.Finding
	perRule, dropped := map[string]int{}, map[string]int{}
	others := 0
	for _, f := range fs {
		f.Rule, f.Evidence = clip(f.Rule, maxRule), clip(f.Evidence, maxEvidence)
		switch {
		case perRule[f.Rule] >= maxFindingsPerRule:
			dropped[f.Rule]++
		case len(kept) >= maxStepFindings:
			others++
		default:
			if perRule[f.Rule] == 0 {
				rules = append(rules, f)
			}
			perRule[f.Rule]++
			kept = append(kept, f)
		}
	}
	for _, first := range rules {
		if n := dropped[first.Rule]; n > 0 {
			kept = append(kept, findings.Finding{
				Source: first.Source, Rule: first.Rule,
				Evidence: fmt.Sprintf("and %d more %s finding(s), left off this step", n, first.Rule),
			})
		}
	}
	if others > 0 {
		kept = append(kept, findings.Finding{
			Source: findings.Code, Rule: ruleMore,
			Evidence: fmt.Sprintf("and %d more finding(s) of other rules, left off this step", others),
		})
	}
	return kept
}

// clip is s cut to at most n bytes, on a character boundary, marked as cut.
func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	const mark = "…"
	return strings.ToValidUTF8(s[:n-len(mark)], "") + mark
}
