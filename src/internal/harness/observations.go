package harness

import (
	"encoding/json"
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

// recorder keeps a run's observations and which of them were answered
// already. It is safe for concurrent use: the MCP reader adds to it while a
// call waits.
type recorder struct {
	mu   sync.Mutex
	now  func() time.Time
	list []Observation
	sent int
}

func (r *recorder) add(kind ObservationKind, detail any) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.list = append(r.list, Observation{At: r.now().UTC(), Kind: kind, Detail: detail})
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
