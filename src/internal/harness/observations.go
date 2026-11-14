package harness

import (
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/JairJosafath/mcp-customs/src/internal/egress"
)

// ObservationKind names what was observed (docs/contracts.md).
type ObservationKind string

// The kinds of observation this harness makes, the egress proxy's among them.
const (
	ObservedDNS         ObservationKind = egress.KindDNS
	ObservedConnect     ObservationKind = egress.KindConnect
	ObservedHTTP        ObservationKind = egress.KindHTTP
	ObservedFile        ObservationKind = "file"
	ObservedSampling    ObservationKind = "sampling"
	ObservedElicitation ObservationKind = "elicitation"
	// ObservedTruncated says the harness stopped recording a kind, once per
	// kind: what the server did of it after may be unseen.
	ObservedTruncated ObservationKind = "truncated"
)

// An Observation is one thing the server under test was seen doing.
type Observation struct {
	At     time.Time       `json:"at"`
	Kind   ObservationKind `json:"kind"`
	Detail any             `json:"detail"`
}

// FileDetail is a file observation's detail: a file the server created or
// changed outside its working directory.
type FileDetail struct {
	Path   string `json:"path"`
	Change string `json:"change"`
}

// RequestDetail is a sampling or elicitation observation's detail: the
// request the server sent, as it sent it.
type RequestDetail struct {
	Method string          `json:"method"`
	Params json.RawMessage `json:"params"`
}

// TruncatedDetail is a truncated observation's detail: the kind no longer
// recorded, and why.
type TruncatedDetail struct {
	Kind ObservationKind `json:"kind"`
	Why  string          `json:"why"`
}

// The caps on what a run records of one kind, so a server can't exhaust
// the harness's memory with observations. Reaching one stops recording
// that kind, with one truncated observation, which is a code finding.
const (
	// maxPerKind is far above what a real server does in a check: the demo
	// servers make a handful of DNS queries, connections and requests, and
	// write a few files; a busy one makes a few hundred.
	maxPerKind = 10_000
	// maxRequestsPerKind bounds sampling and elicitation requests, each of
	// which can be as large as a message (maxMessage). A real server asks
	// once or twice a call, if at all; the demo servers never do.
	maxRequestsPerKind = 100
	// maxBytesPerKind bounds the encoded details of one kind: two of the
	// largest messages a server may send, so one whole request always fits.
	maxBytesPerKind = 2 * maxMessage
)

// recorder keeps a run's observations and which of them were answered
// already. It is safe for concurrent use: the MCP reader adds to it while a
// call waits.
type recorder struct {
	mu   sync.Mutex
	now  func() time.Time
	list []Observation
	sent int
	// count and size are how many observations of each kind were kept and
	// how large their details were; stopped are the kinds no longer kept.
	count   map[ObservationKind]int
	size    map[ObservationKind]int
	stopped map[ObservationKind]bool
}

func newRecorder(now func() time.Time) *recorder {
	return &recorder{now: now, count: map[ObservationKind]int{}, size: map[ObservationKind]int{}, stopped: map[ObservationKind]bool{}}
}

// add records an observation, unless its kind has reached a cap.
func (r *recorder) add(kind ObservationKind, detail any) {
	encoded, err := json.Marshal(detail)
	size := len(encoded)
	if err != nil {
		size = 0
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.stopped[kind] {
		return
	}
	switch {
	case r.count[kind] >= kindCap(kind):
		r.stopLocked(kind, fmt.Sprintf("more than %d %s observations", kindCap(kind), kind))
		return
	case r.size[kind]+size > maxBytesPerKind:
		r.stopLocked(kind, fmt.Sprintf("%s observations over %d MiB", kind, maxBytesPerKind>>20))
		return
	}
	r.count[kind]++
	r.size[kind] += size
	r.list = append(r.list, Observation{At: r.now().UTC(), Kind: kind, Detail: detail})
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

// fresh returns the observations not answered yet, and marks them answered.
func (r *recorder) fresh() []Observation {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := append([]Observation{}, r.list[r.sent:]...)
	r.sent = len(r.list)
	return out
}

// all returns every observation of the run, and marks them answered.
func (r *recorder) all() []Observation {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sent = len(r.list)
	return append([]Observation{}, r.list...)
}
