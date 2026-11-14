package harness

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/JairJosafath/mcp-customs/src/internal/canary"
	"github.com/JairJosafath/mcp-customs/src/internal/egress"
	"github.com/JairJosafath/mcp-customs/src/internal/findings"
	"github.com/JairJosafath/mcp-customs/src/internal/verdict"
)

// asFindings is what the Checker reads of the recorder's observations.
func asFindings(t *testing.T, all []Observation) []findings.Observation {
	t.Helper()
	raw, err := json.Marshal(all)
	if err != nil {
		t.Fatal(err)
	}
	var out []findings.Observation
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

// Flooding a kind past its cap, then doing the bad thing, still blocks:
// past a cap, what would raise a block finding is still recorded.
func TestPastACapWhatWouldBlockIsStillRecorded(t *testing.T) {
	key := canary.Set{{Kind: canary.AWSSecretKey, Value: "test-aws-secret-access-key-0123456789"}}
	tests := []struct {
		name string
		kind ObservationKind
		junk func(i int) any
		leak any
	}{
		{
			"a canary in a DNS name after a flood of queries", ObservedDNS,
			func(i int) any { return egress.DNSDetail{Name: fmt.Sprintf("q%d.example.com", i), Type: "A"} },
			egress.DNSDetail{Name: key[0].Value + ".evil.example", Type: "TXT"},
		},
		{
			"a canary the proxy found after a flood of requests", ObservedHTTP,
			func(i int) any {
				return egress.HTTPDetail{Method: "GET", Host: "a.example", Path: fmt.Sprintf("/%d", i)}
			},
			egress.HTTPDetail{Method: "POST", Host: "evil.example", Path: "/", Canaries: []findings.Match{{Canary: canary.AWSSecretKey, Encoding: findings.Plain}}},
		},
		{
			"a shell's startup file after a flood of writes", ObservedFile,
			func(i int) any { return FileDetail{Path: fmt.Sprintf("/home/dev/!%05d", i), Change: "created"} },
			FileDetail{Path: "/home/dev/.bashrc", Change: "created"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := newRecorder(func() time.Time { return testNow })
			r.setCanaries(key)
			for i := range maxPerKind + 10 {
				r.add(tt.kind, tt.junk(i))
			}
			r.add(tt.kind, tt.leak)
			code := findings.FromObservations(asFindings(t, r.all()), key)
			got := verdict.Decide(verdict.Input{Code: code, ModelVerdict: verdict.Pass})
			if got.Verdict != verdict.Block {
				t.Errorf("verdict %s with findings %+v, want block", got.Verdict, got.Findings)
			}
		})
	}
}

func TestPastACapWhatWouldNotBlockIsDroppedAndTheReserveIsBounded(t *testing.T) {
	r := newRecorder(func() time.Time { return testNow })
	for i := range maxPerKind + maxTellingPerKind*2 {
		r.add(ObservedFile, FileDetail{Path: fmt.Sprintf("/home/dev/%d/.bashrc", i), Change: "created"})
	}
	r.add(ObservedFile, FileDetail{Path: "/home/dev/notes.txt", Change: "created"})
	if got := count(r.all(), ObservedFile); got != maxPerKind+maxTellingPerKind {
		t.Errorf("%d file observations kept, want the cap and the reserve, %d", got, maxPerKind+maxTellingPerKind)
	}
}
