package harness

import (
	"encoding/json"
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
	// ObservedOversized says the harness cut an answer of the server to fit
	// what the Checker reads, with what its scans found in the whole.
	ObservedOversized ObservationKind = "oversized"
	// ObservedRequest is never recorded itself: it names, in a truncated
	// observation, the server's requests the harness stopped answering.
	ObservedRequest ObservationKind = "request"
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
	// Cut says Params is the start of the request's params, as a string:
	// the whole was over maxRequestParams.
	Cut bool `json:"cut,omitempty"`
}

// TruncatedDetail is a truncated observation's detail: the kind no longer
// recorded, and why.
type TruncatedDetail struct {
	Kind ObservationKind `json:"kind"`
	Why  string          `json:"why"`
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
