package checker

import (
	"time"

	"github.com/JairJosafath/mcp-customs/src/internal/findings"
	"github.com/JairJosafath/mcp-customs/src/internal/store"
	"github.com/JairJosafath/mcp-customs/src/internal/verdict"
)

// InstallSpec is what a developer copies to install exactly what was
// approved: the reference, the hash of its whole resolved dependency set,
// and the hash of the approved tool list.
type InstallSpec struct {
	Kind           string `json:"kind"`
	Ref            string `json:"ref"`
	DependencyHash string `json:"dependencySha256"`
	ToolListHash   string `json:"toolListSha256"`
}

// Report is a check's report, reports/<check-id>.json.
type Report struct {
	CheckID     string             `json:"checkId"`
	Submission  store.Submission   `json:"submission"`
	Verdict     verdict.Verdict    `json:"verdict"`
	Findings    []findings.Finding `json:"findings"`
	DecidedBy   string             `json:"decidedBy"`
	SeenBefore  string             `json:"seenBefore,omitempty"`
	InstallSpec InstallSpec        `json:"installSpec"`
	Probes      []probed           `json:"probes"`
	DecidedAt   time.Time          `json:"decidedAt"`
	// Bound says what dynamic analysis can and can't show.
	Bound string `json:"bound"`
}

// boundNote is every report's reminder that a run shows only what the
// server did while watched.
const boundNote = "Dynamic analysis gives a lower bound: it shows what the server did while it was watched, not all it can do."
