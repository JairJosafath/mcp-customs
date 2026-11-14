package harness

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"unicode/utf8"

	"github.com/JairJosafath/mcp-customs/src/internal/findings"
)

// The bounds on what of the server an answer holds, so no answer is larger
// than the 16 MiB the Checker reads (sandbox.maxResponseBytes). Each is
// counted as the Checker encodes it (checkerSize), every byte escaped, and
// is added to the observations an answer carries, at most
// maxObservationsAnswer (about 11.1 MiB).
const (
	// maxCallResult bounds a tool's result, or its error, under the 200 KB
	// a step of the Checker keeps, so a probe of a cut result still fits
	// its step and the check goes on to a verdict.
	maxCallResult = 64 << 10
	// maxInitialize bounds the server's initialize result, which the
	// Checker keeps in a step too.
	maxInitialize = 64 << 10
	// maxResultFinding is the size past which a cut tool result, error or
	// initialize result is an oversized finding itself. Below it, the cut
	// only makes the answer fit a step: real servers' file readers,
	// searches and listings answer more than 64 KiB, the judge reads no
	// more than 4 KiB of a probe and never the initialize result, and every
	// scan runs on the whole value. Past it, half the 16 MiB a message may
	// be, only a server padding its answers is.
	maxResultFinding = 8 << 20
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
// size and SHA-256 as the harness encodes it, what findings.ScanText found
// in all of its strings, and whether the cut is no finding itself.
type OversizedDetail struct {
	What     string             `json:"what"`
	Bytes    int                `json:"bytes"`
	SHA256   string             `json:"sha256"`
	Findings []findings.Finding `json:"findings,omitempty"`
	// CutOnly says the value was cut only to fit a step, under its
	// finding bound: the cut raises no oversized finding, its scans'
	// findings still count.
	CutOnly bool `json:"cutOnly,omitempty"`
}

// CutValue is what an answer holds in place of a value over its bound.
type CutValue struct {
	Cut     bool   `json:"cut"`
	Bytes   int    `json:"bytes"`
	SHA256  string `json:"sha256"`
	Excerpt string `json:"excerpt"`
}

// bounded is v, or, when v encodes to more than limit bytes as the Checker
// encodes it, a CutValue of it, recorded as an oversized observation named
// what: an oversized finding when it is over findingPast, else cut only.
// Every scan runs on the whole value before it is cut.
func (h *Harness) bounded(what string, v any, limit, findingPast int) any {
	raw, err := json.Marshal(v)
	if err != nil {
		return v
	}
	size := checkerSize(raw)
	if size <= limit {
		return v
	}
	text := findings.JSONStrings(raw)
	sum := h.oversized(what, raw, text, size <= findingPast)
	return CutValue{Cut: true, Bytes: len(raw), SHA256: sum, Excerpt: cutHead(text, maxCutExcerpt)}
}

// checkerSize is raw's size once the Checker encodes it again, as a
// probe's failed error is: each byte that isn't UTF-8, which the harness
// answers as it is, becomes \ufffd, six bytes.
func checkerSize(raw []byte) int {
	if utf8.Valid(raw) {
		return len(raw)
	}
	n := len(raw)
	for i := 0; i < len(raw); {
		r, size := utf8.DecodeRune(raw[i:])
		if r == utf8.RuneError && size == 1 {
			n += len(`\ufffd`) - 1
		}
		i += size
	}
	return n
}

// oversized records that the harness cut raw, named what, with the scans
// of text, all of its strings, cut only or an oversized finding, and
// answers its SHA-256.
func (h *Harness) oversized(what string, raw []byte, text string, cutOnly bool) string {
	sum := sha256.Sum256(raw)
	found := findings.ScanText(text).Findings
	if len(found) > maxCutFindings {
		found = found[:maxCutFindings]
	}
	for i := range found {
		found[i].Rule, found[i].Evidence = cutHead(found[i].Rule, maxKind), cutHead(found[i].Evidence, maxCutEvidence)
	}
	d := OversizedDetail{What: what, Bytes: len(raw), SHA256: hex.EncodeToString(sum[:]), Findings: found, CutOnly: cutOnly}
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
	h.oversized("the server's lists", raw, findings.JSONStrings(raw), false)
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
