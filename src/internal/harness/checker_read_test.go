package harness

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/lambdamicrovms"

	"github.com/JairJosafath/mcp-customs/src/internal/checker/sandbox"
	"github.com/JairJosafath/mcp-customs/src/internal/findings"
	"github.com/JairJosafath/mcp-customs/src/internal/verdict"
)

// tokenAPI is Lambda MicroVMs as far as a call needs it: an endpoint token.
type tokenAPI struct{ sandbox.API }

func (tokenAPI) CreateMicrovmAuthToken(context.Context, *lambdamicrovms.CreateMicrovmAuthTokenInput, ...func(*lambdamicrovms.Options)) (*lambdamicrovms.CreateMicrovmAuthTokenOutput, error) {
	return &lambdamicrovms.CreateMicrovmAuthTokenOutput{AuthToken: map[string]string{"X-aws-proxy-auth": "jwe"}}, nil
}

// harnessDoer answers the Checker's calls with the harness itself.
type harnessDoer struct{ h *Harness }

func (d harnessDoer) Do(req *http.Request) (*http.Response, error) {
	rec := httptest.NewRecorder()
	d.h.ServeHTTP(rec, req)
	return rec.Result(), nil
}

// A server that floods every kind it can, sampling with the largest
// messages among them, still leaves an answer the Checker reads whole: the
// caps are reached, and the verdict, decided by code, is review.
func TestAFloodedRunIsReadWholeByTheCheckerAndEndsAtReview(t *testing.T) {
	run := newTestRun(t, &fakeInstaller{})
	server, stdout := io.Pipe()
	c := newConn(io.Discard, server, run.h.obs)
	go func() {
		params := `{"messages":"` + strings.Repeat("x", maxMessage-1024) + `"}`
		for i := range 3 {
			_, _ = fmt.Fprintf(stdout, `{"jsonrpc":"2.0","id":%d,"method":"sampling/createMessage","params":%s}`+"\n", i, params)
		}
		_ = stdout.Close()
	}()
	<-c.closed
	name := strings.Repeat("a", 2000)
	for i := range maxPerKind + 1 {
		for _, k := range []ObservationKind{ObservedDNS, ObservedConnect, ObservedHTTP, ObservedFile} {
			run.h.obs.add(k, map[string]any{"name": name, "i": i})
		}
	}

	checker := sandbox.NewMicroVMs(tokenAPI{}, harnessDoer{run.h}, sandbox.Config{})
	resp, err := checker.Call(t.Context(), sandbox.VM{ID: "mvm-1", Endpoint: "harness.example", Token: testToken}, sandbox.Request{Method: http.MethodGet, Path: "/observations"})
	if err != nil {
		t.Fatalf("the Checker could not read GET /observations: %v", err)
	}
	var all struct {
		Observations []findings.Observation `json:"observations"`
	}
	if err := json.Unmarshal(resp.Body, &all); err != nil {
		t.Fatal(err)
	}
	got := verdict.Decide(verdict.Input{Code: findings.FromObservations(all.Observations, nil), ModelVerdict: verdict.Pass})
	if got.Verdict != verdict.Review {
		t.Errorf("verdict %s, want review", got.Verdict)
	}
	truncated := 0
	for _, f := range got.Findings {
		if f.Rule == findings.RuleTruncated {
			truncated++
		}
	}
	if truncated < 4 {
		t.Errorf("%d %s findings in %+v, want one for each flooded kind", truncated, findings.RuleTruncated, got.Findings)
	}
	t.Logf("GET /observations answered %d bytes", len(resp.Body))
}
