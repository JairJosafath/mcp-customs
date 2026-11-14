package harness

import (
	"encoding/json"
	"fmt"
	"slices"
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
)

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
	if r.telling[kind] < maxTellingPerKind && r.tellingSize+size <= maxTellingBytes && r.tellsLocked(kind, detail) {
		r.telling[kind]++
		r.tellingSize += size
		r.list = append(r.list, o)
	}
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
// canary leaving, or a write to an agent's config or a shell's startup.
func (r *recorder) tellsLocked(kind ObservationKind, detail any) bool {
	raw, err := json.Marshal(detail)
	if err != nil {
		return false
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

func (r *recorder) stopLocked(kind ObservationKind, why string) {
	r.stopped[kind] = true
	r.list = append(r.list, Observation{At: r.now().UTC(), Kind: ObservedTruncated, Detail: TruncatedDetail{Kind: kind, Why: why}})
}

func kindCap(kind ObservationKind) int {
	if kind == ObservedSampling || kind == ObservedElicitation {
		return maxRequestsPerKind
	}
	return maxPerKind
}
