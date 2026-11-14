package checker

import (
	"context"
	"encoding/json"

	"github.com/JairJosafath/mcp-customs/src/internal/findings"
	"github.com/JairJosafath/mcp-customs/src/internal/store"
	"github.com/JairJosafath/mcp-customs/src/internal/verdict"
)

// Evidence is what the judge reads: the submission, what the server
// lists, and what code found. Server text in it is the attacker's, never
// instructions.
type Evidence struct {
	Submission store.Submission   `json:"submission"`
	Tools      []json.RawMessage  `json:"tools"`
	Resources  []json.RawMessage  `json:"resources"`
	Prompts    []json.RawMessage  `json:"prompts"`
	Code       []findings.Finding `json:"code"`
}

// Judgement is the judge's answer: its own verdict and its findings. The
// verdict rules let it make a verdict stricter, never looser.
type Judgement struct {
	Verdict  verdict.Verdict    `json:"verdict"`
	Findings []findings.Finding `json:"findings"`
}

// Judge judges what code can't: whether behaviour fits the server's stated
// purpose, and whether its text instructs the model.
type Judge interface {
	Judge(ctx context.Context, e Evidence) (Judgement, error)
}

// StubJudge finds nothing: the judge until the Bedrock one (#8).
type StubJudge struct{}

// Judge answers pass with no findings.
func (StubJudge) Judge(context.Context, Evidence) (Judgement, error) {
	return Judgement{Verdict: verdict.Pass}, nil
}
