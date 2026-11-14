package harness

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"testing"
)

func TestSealEndsEgressIsIdempotentAndAllowAfterItIsAConflict(t *testing.T) {
	eg := &fakeEgress{}
	run := newTestRunWith(t, func(c *Config) { c.Egress = eg })
	if status, _ := run.do(t, "POST", "/allow", map[string]any{"hosts": []string{"api.weather.example"}}); status != http.StatusOK {
		t.Fatalf("POST /allow before the seal = %d", status)
	}
	for range 2 {
		status, body := run.do(t, "POST", "/seal", map[string]any{})
		if status != http.StatusOK || !jsonEqual(t, body["hosts"], json.RawMessage(`[]`)) {
			t.Errorf("POST /seal = %d %v, want 200 and an empty allowlist", status, body)
		}
	}
	if eg.seals == 0 || len(eg.allowed) != 0 {
		t.Errorf("the proxy was sealed %d times, allowing %v; want sealed, allowing nothing", eg.seals, eg.allowed)
	}
	if status, _ := run.do(t, "POST", "/allow", map[string]any{"hosts": []string{"api.weather.example"}}); status != http.StatusConflict {
		t.Errorf("POST /allow after the seal = %d, want 409", status)
	}
	if len(eg.allowed) != 0 {
		t.Errorf("the proxy allows %v after the seal", eg.allowed)
	}
}

func TestSealWithoutAnEgressProxyIsAConflict(t *testing.T) {
	run := newTestRun(t, &fakeInstaller{})
	if status, _ := run.do(t, "POST", "/seal", map[string]any{}); status != http.StatusConflict {
		t.Errorf("POST /seal = %d, want 409: there is nothing to seal", status)
	}
}

func TestTheInvestigationsRoutesWorkAfterTheSealAndReopenNothing(t *testing.T) {
	eg := &fakeEgress{}
	ft := fakeTimeIn(t.TempDir())
	inst := &fakeInstaller{}
	run := newTestRunWith(t, func(c *Config) { c.Egress, c.FakeTime, c.Installer = eg, ft, inst })
	pkg := filepath.Join(run.workdir, "node_modules", "weather")
	written := filepath.Join(run.home, ".cache", "x")
	inst.out = Installed{Resolved: []byte("{}"), Command: []string{"weather"}, Source: pkg}
	inst.write = func(Sandbox) {
		must(t, os.MkdirAll(pkg, 0o750))
		must(t, os.WriteFile(filepath.Join(pkg, "index.js"), []byte("main()"), 0o600))
		must(t, os.MkdirAll(filepath.Dir(written), 0o750))
		must(t, os.WriteFile(written, []byte("x"), 0o600))
	}
	if status, body := run.do(t, "POST", "/install", installBody("npm", "weather@1.0.0")); status != http.StatusOK {
		t.Fatalf("POST /install = %d %v", status, body)
	}
	if status, _ := run.do(t, "POST", "/seal", map[string]any{}); status != http.StatusOK {
		t.Fatalf("POST /seal = %d", status)
	}
	for route, body := range map[string]any{
		"/clock":    map[string]any{"offset": "720h"},
		"/source":   map[string]any{"path": "index.js"},
		"/download": map[string]any{"path": written},
	} {
		if status, answer := run.do(t, "POST", route, body); status != http.StatusOK {
			t.Errorf("POST %s after the seal = %d %v, want 200", route, status, answer)
		}
	}
	if len(eg.allowed) != 0 {
		t.Errorf("the proxy allows %v after the seal", eg.allowed)
	}
}
