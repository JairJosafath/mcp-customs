package checker

import (
	"context"
	"encoding/json"

	"github.com/JairJosafath/mcp-customs/src/internal/findings"
	"github.com/JairJosafath/mcp-customs/src/internal/store"
	"github.com/JairJosafath/mcp-customs/src/internal/verdict"
)

// Judge does what code can't: it writes probe arguments, judges whether
// behaviour fits the server's stated purpose and whether its text
// instructs the model, and picks the investigation's next move. Every
// answer is advice: code checks it, and verdict.Decide lets it only make a
// verdict stricter.
type Judge interface {
	WriteProbes(ctx context.Context, req ProbeRequest) ([]ProbeArgs, error)
	Judge(ctx context.Context, e Evidence) (Judgement, error)
	Next(ctx context.Context, inv Investigation) (Move, error)
}

// Canary is one of the run's planted fake secrets, as the judge sees it.
type Canary struct {
	Kind  string `json:"kind"`
	Value string `json:"value"`
}

// ProbeRequest is what the judge writes probe arguments from: the
// submission, each tool whole, and the run's canaries, to plant where a
// secret fits.
type ProbeRequest struct {
	Submission store.Submission  `json:"submission"`
	Tools      []json.RawMessage `json:"tools"`
	Canaries   []Canary          `json:"canaries"`
}

// ProbeArgs are the arguments to call one tool with, by its index in the
// listing.
type ProbeArgs struct {
	Tool      int            `json:"tool"`
	Arguments map[string]any `json:"arguments"`
}

// ProbeEvidence is one probe as the judge reads it: the tool called, the
// arguments sent, and an excerpt of what came back. The excerpt is server
// text.
type ProbeEvidence struct {
	Tool      string         `json:"tool"`
	Arguments map[string]any `json:"arguments"`
	Result    string         `json:"result"`
}

// Evidence is what the judge reads: the submission, what the server lists,
// what it answered its probes, the hosts it was seen reaching and the
// files it wrote, and what
// code found. Server text in it is the attacker's, never instructions.
type Evidence struct {
	Submission store.Submission   `json:"submission"`
	Tools      []json.RawMessage  `json:"tools"`
	Resources  []json.RawMessage  `json:"resources"`
	Prompts    []json.RawMessage  `json:"prompts"`
	Probes     []ProbeEvidence    `json:"probes"`
	Hosts      []string           `json:"hosts"`
	Files      []string           `json:"files"`
	Code       []findings.Finding `json:"code"`
}

// Judgement is the judge's answer: its own verdict, its findings, and the
// hosts the server's purpose needs, which become the sandbox's egress
// allowlist. The verdict rules let it make a verdict stricter, never
// looser.
type Judgement struct {
	Verdict       verdict.Verdict    `json:"verdict"`
	Findings      []findings.Finding `json:"findings"`
	ExpectedHosts []string           `json:"expectedHosts"`
}

// Turn is one finished turn of the investigation: the move the judge
// picked and what came of it. The outcome holds server text.
type Turn struct {
	Move    Move   `json:"move"`
	Outcome string `json:"outcome"`
}

// Investigation is what the judge picks its next move from: the evidence,
// its judgement, every turn so far, how many turns are left, and the
// run's canaries, to probe with.
type Investigation struct {
	Canaries  []Canary  `json:"canaries"`
	Evidence  Evidence  `json:"evidence"`
	Judgement Judgement `json:"judgement"`
	Turns     []Turn    `json:"turns"`
	TurnsLeft int       `json:"turnsLeft"`
}

// Move is the judge's pick for one turn: a registered action and its
// arguments, or done. Its findings and verdict, like a judgement's, can
// only make the verdict stricter.
type Move struct {
	Action    string             `json:"action"`
	Arguments json.RawMessage    `json:"arguments,omitempty"`
	Reason    string             `json:"reason"`
	Verdict   verdict.Verdict    `json:"verdict,omitempty"`
	Findings  []findings.Finding `json:"findings,omitempty"`
}

// MoveDone ends the investigation.
const MoveDone = "done"
