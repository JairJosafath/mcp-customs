package harness

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"

	"github.com/JairJosafath/mcp-customs/src/internal/findings"
)

// The bounds on what of the server an answer holds, so no answer is larger
// than the 16 MiB the Checker reads (sandbox.maxResponseBytes). Each is
// counted as encoded, every byte escaped, and is added to the observations
// an answer carries, at most maxObservationsAnswer (about 10.1 MiB).
const (
	// maxCallResult bounds a tool's result, or its error, under the 200 KB
	// a step of the Checker keeps, so a probe of a cut result still fits
	// its step and the check goes on to a verdict.
	maxCallResult = 64 << 10
	// maxInitialize bounds the server's initialize result, which the
	// Checker keeps in a step too.
	maxInitialize = 64 << 10
	// maxLists bounds the tools, resources and prompts /list answers
	// together: far above a real server's, and above the 200 KB a step
	// keeps, so a cut list never passes as a whole one.
	maxLists = 4 << 20
	// maxDependencies bounds the resolved dependency set /install answers;
	// its SHA-256 is always of the whole set.
	maxDependencies = 1 << 20
	// maxAnswerMessage bounds an answer's message, which may quote the
	// server, such as a JSON-RPC error's.
	maxAnswerMessage = 4 << 10
	// maxCutExcerpt bounds the text a cut value keeps: its strings, as the
	// Checker reads them, from the start.
	maxCutExcerpt = 8 << 10
	// maxCutFindings and maxCutEvidence bound what an oversized
	// observation keeps of the scans of the whole value, so it is always
	// under maxTellingObservation and is never dropped or compacted.
	maxCutFindings = 24
	maxCutEvidence = 128
)

// OversizedDetail is an oversized observation's detail: what was cut, its
// size and SHA-256 as the harness encodes it, and what findings.ScanText
// found in all of its strings.
type OversizedDetail struct {
	What     string             `json:"what"`
	Bytes    int                `json:"bytes"`
	SHA256   string             `json:"sha256"`
	Findings []findings.Finding `json:"findings,omitempty"`
}

// CutValue is what an answer holds in place of a value over its bound.
type CutValue struct {
	Cut     bool   `json:"cut"`
	Bytes   int    `json:"bytes"`
	SHA256  string `json:"sha256"`
	Excerpt string `json:"excerpt"`
}

// bounded is v, or, when v encodes to more than limit bytes, a CutValue
// of it, recorded as an oversized observation named what. Every scan runs
// on the whole value before it is cut.
func (h *Harness) bounded(what string, v any, limit int) any {
	raw, err := json.Marshal(v)
	if err != nil || len(raw) <= limit {
		return v
	}
	text := findings.JSONStrings(raw)
	sum := h.oversized(what, raw, text)
	return CutValue{Cut: true, Bytes: len(raw), SHA256: sum, Excerpt: cutHead(text, maxCutExcerpt)}
}

// oversized records that the harness cut raw, named what, with the scans
// of text, all of its strings, and answers its SHA-256.
func (h *Harness) oversized(what string, raw []byte, text string) string {
	sum := sha256.Sum256(raw)
	found := findings.ScanText(text).Findings
	if len(found) > maxCutFindings {
		found = found[:maxCutFindings]
	}
	for i := range found {
		found[i].Rule, found[i].Evidence = cutHead(found[i].Rule, maxKind), cutHead(found[i].Evidence, maxCutEvidence)
	}
	d := OversizedDetail{What: what, Bytes: len(raw), SHA256: hex.EncodeToString(sum[:]), Findings: found}
	h.obs.add(ObservedOversized, d)
	return d.SHA256
}

// listFields are the lists /list answers, in the order a cut keeps them.
var listFields = []string{"tools", "resources", "prompts"}

// boundLists is lists, or, when they encode to more than maxLists bytes,
// or were cut while read, as many of their items as fit, in order, marked
// cut and recorded as an oversized observation, scanned whole as read.
func (h *Harness) boundLists(lists answer, cut bool) answer {
	raw, err := json.Marshal(lists)
	if err != nil || (len(raw) <= maxLists && !cut) {
		return lists
	}
	h.oversized("the server's lists", raw, findings.JSONStrings(raw))
	budget := maxLists
	out := answer{"cut": true}
	for _, field := range listFields {
		items, _ := lists[field].([]json.RawMessage)
		kept := []json.RawMessage{}
		for _, item := range items {
			b, err := json.Marshal(item)
			if err != nil || len(b)+1 > budget {
				budget = 0
				break
			}
			budget -= len(b) + 1
			kept = append(kept, item)
		}
		out[field] = kept
	}
	return out
}
