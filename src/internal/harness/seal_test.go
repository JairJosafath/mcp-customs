package harness

import (
	"encoding/json"
	"net/http"
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
