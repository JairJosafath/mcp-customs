package checker

import (
	"encoding/json"
	"errors"
	"fmt"

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
