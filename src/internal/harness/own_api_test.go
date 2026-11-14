package harness

import (
	"net/http"
	"slices"
	"testing"
)

func TestAllowAndInstallRefuseTheStacksOwnAPIHost(t *testing.T) {
	const api = "abc123.execute-api.eu-west-1.amazonaws.com"
	for _, host := range []string{api, "ABC123.execute-api.eu-west-1.amazonaws.com."} {
		eg := &fakeEgress{}
		run := newTestRunWith(t, func(c *Config) { c.Egress, c.APIHost = eg, api })
		if status, _ := run.do(t, "POST", "/allow", map[string]any{"hosts": []string{"api.weather.example", host}}); status != http.StatusForbidden {
			t.Errorf("POST /allow %q = %d, want 403", host, status)
		}
		install := map[string]any{"kind": "go", "ref": "example.com/weather@v1.0.0", "allowHosts": []string{host}}
		if status, _ := run.do(t, "POST", "/install", install); status != http.StatusForbidden {
			t.Errorf("POST /install allowing %q = %d, want 403", host, status)
		}
		if len(eg.allowed) != 0 {
			t.Errorf("allowed %v, want nothing", eg.allowed)
		}
		// Any other host is still the Checker's to allow.
		if status, _ := run.do(t, "POST", "/allow", map[string]any{"hosts": []string{"api.weather.example"}}); status != http.StatusOK || !slices.Equal(eg.allowed, []string{"api.weather.example"}) {
			t.Errorf("POST /allow = %d, allowed %v; want 200 and the host", status, eg.allowed)
		}
	}
}
