package harness

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func truncations(list []Observation) []TruncatedDetail {
	var out []TruncatedDetail
	for _, o := range list {
		if d, ok := o.Detail.(TruncatedDetail); ok && o.Kind == ObservedTruncated {
			out = append(out, d)
		}
	}
	return out
}

func count(list []Observation, kind ObservationKind) int {
	n := 0
	for _, o := range list {
		if o.Kind == kind {
			n++
		}
	}
	return n
}

func TestReachingACapStopsRecordingThatKindWithOneTruncatedObservation(t *testing.T) {
	tests := []struct {
		name string
		kind ObservationKind
		cap  int
	}{
		{"dns", ObservedDNS, maxPerKind},
		{"file", ObservedFile, maxPerKind},
		{"sampling", ObservedSampling, maxRequestsPerKind},
		{"elicitation", ObservedElicitation, maxRequestsPerKind},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := newRecorder(func() time.Time { return testNow })
			for range tt.cap + 50 {
				r.add(tt.kind, map[string]string{"name": "a.example"})
			}
			r.add(ObservedHTTP, map[string]string{"host": "b.example"})
			all := r.all()
			if got := count(all, tt.kind); got != tt.cap {
				t.Errorf("%d %s observations kept, want the cap, %d", got, tt.kind, tt.cap)
			}
			if got := truncations(all); len(got) != 1 || got[0].Kind != tt.kind {
				t.Errorf("truncated observations %+v, want one of %s", got, tt.kind)
			}
			if count(all, ObservedHTTP) != 1 {
				t.Error("another kind stopped being recorded")
			}
		})
	}
}

func TestABytesCapStopsRecordingThatKind(t *testing.T) {
	tests := []struct {
		name  string
		kinds []ObservationKind
		why   string
	}{
		{"one kind over its own cap", []ObservationKind{ObservedHTTP}, "http observations over 2 MiB"},
		{"every kind together over the run's cap", []ObservationKind{ObservedDNS, ObservedConnect, ObservedHTTP, ObservedFile, ObservedHook}, "the run's observations over 8 MiB"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := newRecorder(func() time.Time { return testNow })
			big := map[string]string{"path": strings.Repeat("x", 64<<10)}
			for range 200 {
				for _, k := range tt.kinds {
					r.add(k, big)
				}
			}
			all := r.all()
			got := truncations(all)
			if len(got) == 0 || got[0].Why != tt.why {
				t.Errorf("truncated observations %+v, want the first saying %q", got, tt.why)
			}
			if raw, _ := json.Marshal(all); len(raw) > maxObservedBytes+maxTellingBytes {
				t.Errorf("the observations encode to %d bytes, over the budget", len(raw))
			}
		})
	}
}

func TestTruncateRecordsOncePerKindAndStopsIt(t *testing.T) {
	r := newRecorder(func() time.Time { return testNow })
	r.truncate(ObservedFile, "the file watch stopped")
	r.truncate(ObservedFile, "the file watch stopped")
	r.add(ObservedFile, FileDetail{Path: "/home/dev/notes.txt", Change: "created"})
	all := r.all()
	if len(all) != 1 || len(truncations(all)) != 1 {
		t.Errorf("observations %+v, want one truncated and nothing after", all)
	}
}
