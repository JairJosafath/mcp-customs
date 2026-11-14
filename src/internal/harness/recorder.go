package harness

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/JairJosafath/mcp-customs/src/internal/canary"
	"github.com/JairJosafath/mcp-customs/src/internal/findings"
)

// The caps on what a run records, so a server can't exhaust the harness's
// memory, nor make an answer larger than the Checker reads (16 MiB, its
// sandbox.maxResponseBytes). Reaching one stops recording that kind, with
// one truncated observation, which is a code finding. Every observation is
// counted as encoded, so all of them together, the telling ones past a
// cap and the truncated ones included, stay under 11 MiB.
const (
	// maxPerKind is far above what a real server does in a check: the demo
	// servers make a handful of DNS queries, connections and requests, and
	// write a few files; a busy one makes a few hundred.
	maxPerKind = 5_000
	// maxRequestsPerKind bounds sampling and elicitation requests. A real
	// server asks once or twice a call, if at all; the demo servers never do.
	maxRequestsPerKind = 100
	// maxBytesPerKind bounds one kind, so a flood of one leaves room for
	// the others: 5,000 network observations of a few hundred bytes fit.
	maxBytesPerKind = 2 << 20
	// maxObservedBytes bounds every kind together.
	maxObservedBytes = 8 << 20
	// maxTellingPerKind and maxTellingBytes bound what is still recorded
	// of a kind past its cap: observations that would raise a block
	// finding, so a flood can't hide a leak. A server that leaks that often
	// is blocked by those already kept.
	maxTellingPerKind = 200
	maxTellingBytes   = 2 << 20
	// maxRequestParams bounds what a sampling or elicitation observation
	// keeps of the request's params; past it, the start is kept as a string.
	maxRequestParams = 64 << 10
	// maxTellingObservation bounds one telling observation as kept: a
	// larger one, such as a request with a padded path, is kept compact
	// (compactLocked), never dropped. A file observation, whose path is at
	// most PATH_MAX (4096 bytes), fits whole even with every byte escaped.
	maxTellingObservation = 32 << 10
	// maxTruncations bounds the truncated observations, one per kind; the
	// kinds are the harness's and the egress's, about ten.
	maxTruncations = 32
	// maxWhy and maxKind bound the strings of a truncated observation, so
	// it is at most maxTruncatedSize encoded, every byte escaped.
	maxWhy           = 256
	maxKind          = 64
	maxTruncatedSize = 6*(maxWhy+2*maxKind) + 128
	// maxObservationsAnswer bounds every observation a run keeps, encoded
	// as an answer's "observations": what GET /observations answers at
	// most, under the 16 MiB the Checker reads.
	maxObservationsAnswer = maxObservedBytes + maxTellingBytes + maxTruncations*maxTruncatedSize + 64
)

// CompactDetail is what a telling observation over maxTellingObservation
// keeps: its host or path, cut, and the canaries found in the whole of it.
// Its block finding comes from those, as the whole observation's would.
type CompactDetail struct {
	Host     string           `json:"host,omitempty"`
	Path     string           `json:"path,omitempty"`
	Canaries []findings.Match `json:"canaries,omitempty"`
	Cut      bool             `json:"cut"`
}

// maxCompactText bounds a compact observation's host and path.
const maxCompactText = 1024

// blockRules are the findings an observation past a cap is still kept for.
var blockRules = []string{findings.RuleCanaryLeft, findings.RuleAgentConfig, findings.RuleShellStartup}

// recorder keeps a run's observations and which of them were answered
// already. It is safe for concurrent use: the MCP reader adds to it while a
// call waits.
type recorder struct {
	mu       sync.Mutex
	now      func() time.Time
	canaries canary.Set
	list     []Observation
	sent     int
	// count and size are how many observations of each kind were kept and
	// how large they were encoded, total all of them; stopped are the
	// kinds no longer kept but for telling ones, counted in telling and
	// tellingSize.
	count       map[ObservationKind]int
	size        map[ObservationKind]int
	total       int
	stopped     map[ObservationKind]bool
	telling     map[ObservationKind]int
	tellingSize int
	truncations int
}

func newRecorder(now func() time.Time) *recorder {
	return &recorder{
		now: now, count: map[ObservationKind]int{}, size: map[ObservationKind]int{},
		stopped: map[ObservationKind]bool{}, telling: map[ObservationKind]int{},
	}
}

// setCanaries names the run's canaries, which an observation past a cap is
// searched for.
func (r *recorder) setCanaries(c canary.Set) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.canaries = c
}

// add records an observation, unless its kind has reached a cap and it
// would raise no block finding.
func (r *recorder) add(kind ObservationKind, detail any) {
	o := Observation{At: r.now().UTC(), Kind: kind, Detail: detail}
	encoded, err := json.Marshal(o)
	if err != nil {
		return
	}
	size := len(encoded) + 1
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.stopped[kind] {
		why := r.overLocked(kind, size)
		if why == "" {
			r.count[kind]++
			r.size[kind] += size
			r.total += size
			r.list = append(r.list, o)
			return
		}
		r.stopLocked(kind, why)
	}
	r.keepTellingLocked(o, size)
}

// keepTellingLocked keeps o past its kind's cap if it would raise a block
// finding, compact when it is large. Only a reserve already holding
// telling observations, each a block finding itself, refuses one.
func (r *recorder) keepTellingLocked(o Observation, size int) {
	if r.telling[o.Kind] >= maxTellingPerKind {
		return
	}
	raw, err := json.Marshal(o.Detail)
	if err != nil || !r.tellsLocked(o.Kind, raw) {
		return
	}
	if size > maxTellingObservation {
		o, size = r.compactLocked(o, raw)
	}
	if r.tellingSize+size > maxTellingBytes {
		return
	}
	r.telling[o.Kind]++
	r.tellingSize += size
	r.list = append(r.list, o)
}

// compactLocked is o, whose detail is raw, as a CompactDetail.
func (r *recorder) compactLocked(o Observation, raw json.RawMessage) (Observation, int) {
	var d struct {
		Host     string           `json:"host"`
		Path     string           `json:"path"`
		Canaries []findings.Match `json:"canaries"`
	}
	_ = json.Unmarshal(raw, &d)
	var matches []findings.Match
	for _, m := range append(d.Canaries, findings.MatchCanaries(raw, r.canaries)...) {
		if !slices.Contains(matches, m) {
			matches = append(matches, m)
		}
	}
	o.Detail = CompactDetail{Host: cutHead(d.Host, maxCompactText), Path: cutTail(d.Path, maxCompactText), Canaries: matches, Cut: true}
	encoded, err := json.Marshal(o)
	if err != nil {
		return o, maxTellingBytes + 1
	}
	return o, len(encoded) + 1
}

// overLocked says which cap an observation of kind, size bytes encoded,
// would pass, or "".
func (r *recorder) overLocked(kind ObservationKind, size int) string {
	switch {
	case r.count[kind] >= kindCap(kind):
		return fmt.Sprintf("more than %d %s observations", kindCap(kind), kind)
	case r.size[kind]+size > maxBytesPerKind:
		return fmt.Sprintf("%s observations over %d MiB", kind, maxBytesPerKind>>20)
	case r.total+size > maxObservedBytes:
		return fmt.Sprintf("the run's observations over %d MiB", maxObservedBytes>>20)
	}
	return ""
}

// tellsLocked says whether an observation would raise a block finding: a
// canary leaving, or a write to an agent's config or a shell's startup. An
// oversized one tells too: the scans of what was cut are nowhere else.
func (r *recorder) tellsLocked(kind ObservationKind, raw json.RawMessage) bool {
	if kind == ObservedOversized {
		return true
	}
	found := findings.FromObservations([]findings.Observation{{Kind: string(kind), Detail: raw}}, r.canaries)
	return slices.ContainsFunc(found, func(f findings.Finding) bool { return slices.Contains(blockRules, f.Rule) })
}

// truncate stops recording kind, for why, with one truncated observation.
func (r *recorder) truncate(kind ObservationKind, why string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.stopped[kind] {
		r.stopLocked(kind, why)
	}
}

// stopLocked stops recording kind, with one truncated observation, its
// strings bounded, while fewer than maxTruncations were made.
func (r *recorder) stopLocked(kind ObservationKind, why string) {
	r.stopped[kind] = true
	if r.truncations >= maxTruncations {
		return
	}
	r.truncations++
	detail := TruncatedDetail{Kind: ObservationKind(cutHead(string(kind), maxKind)), Why: cutHead(why, maxWhy)}
	r.list = append(r.list, Observation{At: r.now().UTC(), Kind: ObservedTruncated, Detail: detail})
}

// cutHead is s cut to at most n bytes, from its start; cutTail from its
// end.
// Neither splits a character.
func cutHead(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return strings.ToValidUTF8(s[:n], "")
}

func cutTail(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return strings.ToValidUTF8(s[len(s)-n:], "")
}

func kindCap(kind ObservationKind) int {
	if kind == ObservedSampling || kind == ObservedElicitation {
		return maxRequestsPerKind
	}
	return maxPerKind
}
