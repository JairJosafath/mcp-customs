package harness

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/JairJosafath/mcp-customs/src/internal/canary"
	"github.com/JairJosafath/mcp-customs/src/internal/checker/sandbox"
	"github.com/JairJosafath/mcp-customs/src/internal/egress"
	"github.com/JairJosafath/mcp-customs/src/internal/findings"
)

// checkerReads is what the Checker reads of an answer at most
// (sandbox.maxResponseBytes).
const checkerReads = 16 << 20

func TestTheObservationsBoundIsUnderWhatTheCheckerReads(t *testing.T) {
	if maxObservationsAnswer >= checkerReads {
		t.Errorf("observations may take %d bytes, not under the %d the Checker reads", maxObservationsAnswer, checkerReads)
	}
}

// floodEveryKind drives r's observations to their worst: every kind
// flooded past its caps with characters JSON escapes sixfold, the telling
// reserve filled, whole and compact, the oversized one with cuts at their
// largest, more kinds truncated than the harness has, with server text as
// long as a message, and requests with padded methods past the pending cap.
func floodEveryKind(t *testing.T, r *recorder) {
	t.Helper()
	key := canaryList(testCanaries)
	escaped := strings.Repeat("<", 3000)
	kinds := []ObservationKind{ObservedDNS, ObservedConnect, ObservedHTTP, ObservedFile, ObservedSampling, ObservedElicitation, ObservedHook}
	for i := range maxTruncations + 8 {
		kinds = append(kinds, ObservationKind(fmt.Sprintf("%s-%d", strings.Repeat("<", 1<<10), i)))
	}
	_, server := io.Pipe()
	stdout, w := io.Pipe()
	c := newConn(server, stdout, r)
	method := strings.Repeat("<", 1<<20)
	go func() {
		for i := range maxPending + 8 {
			_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":`+strconv.Itoa(i)+`,"method":"`+method+`","params":{}}`+"\n")
		}
		_ = w.Close()
	}()
	<-c.closed
	// Kinds the harness doesn't have, truncated with server text, before
	// the harness's own are flooded past their caps.
	why := strings.Repeat("<", maxMessage)
	for _, k := range kinds[7:] {
		r.truncate(k, why)
	}
	for _, k := range kinds[:7] {
		for range 200 {
			r.add(k, map[string]string{"name": escaped})
		}
	}
	// A few large ones, kept compact.
	for range 10 {
		r.add(ObservedHTTP, egress.HTTPDetail{Host: escaped, Path: strings.Repeat("<", 64<<10), Canaries: []findings.Match{{Canary: canary.GitHubToken, Encoding: findings.Plain}}})
	}
	for range maxTellingPerKind {
		r.add(ObservedDNS, egress.DNSDetail{Name: escaped + key[0].Value + ".evil.example"})
		r.add(ObservedFile, FileDetail{Path: "/home/dev/" + strings.Repeat("<", 4000) + "/.bashrc", Change: "created"})
	}
	for range maxTellingPerKind {
		r.add(ObservedOversized, largestCut())
	}
}

// largestCut is an oversized observation's detail at its largest: every
// finding it keeps, each evidence escaped sixfold.
func largestCut() OversizedDetail {
	found := make([]findings.Finding, maxCutFindings)
	for i := range found {
		found[i] = findings.Finding{Source: findings.Code, Rule: strings.Repeat("<", maxKind), Evidence: strings.Repeat("<", maxCutEvidence)}
	}
	return OversizedDetail{What: "the result of tools/call", Bytes: maxMessage, SHA256: strings.Repeat("0", 64), Findings: found}
}

// The worst a server can make of GET /observations: every kind flooded
// past its caps with characters JSON escapes sixfold, the reserve filled
// with telling observations, whole and compact, more kinds truncated than
// the harness has, with server text as long as a message, and requests
// with padded methods past the pending cap. The Checker still reads it
// whole, and it is within maxObservationsAnswer.
func TestTheWorstObservationsAnswerIsReadWholeByTheChecker(t *testing.T) {
	run := newTestRun(t, &fakeInstaller{})
	floodEveryKind(t, run.h.obs)

	checker := sandbox.NewMicroVMs(tokenAPI{}, harnessDoer{run.h}, sandbox.Config{})
	resp, err := checker.Call(t.Context(), sandbox.VM{ID: "mvm-1", Endpoint: "harness.example", Token: testToken}, sandbox.Request{Method: http.MethodGet, Path: "/observations"})
	if err != nil {
		t.Fatalf("the Checker could not read GET /observations: %v", err)
	}
	if len(resp.Body) > maxObservationsAnswer {
		t.Errorf("GET /observations answered %d bytes, over the bound of %d", len(resp.Body), maxObservationsAnswer)
	}
	var all struct {
		Observations []struct {
			Kind   ObservationKind `json:"kind"`
			Detail TruncatedDetail `json:"detail"`
		} `json:"observations"`
	}
	if err := json.Unmarshal(resp.Body, &all); err != nil {
		t.Fatal(err)
	}
	truncated := 0
	for _, o := range all.Observations {
		if o.Kind != ObservedTruncated {
			continue
		}
		truncated++
		if len(o.Detail.Kind) > maxKind || len(o.Detail.Why) > maxWhy {
			t.Errorf("a truncated observation of %d and %d bytes, over %d and %d", len(o.Detail.Kind), len(o.Detail.Why), maxKind, maxWhy)
		}
	}
	if truncated > maxTruncations {
		t.Errorf("%d truncated observations, over %d", truncated, maxTruncations)
	}
	t.Logf("GET /observations answered %d bytes; the bound is %d, the Checker reads %d", len(resp.Body), maxObservationsAnswer, checkerReads)
}
