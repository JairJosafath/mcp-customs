package harness

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"slices"
	"testing"
	"time"
)

func TestAllowAndInstallRefuseEveryFormOfTheStacksOwnAPIHost(t *testing.T) {
	for _, host := range []string{
		testAPIHost,
		"ABC123.execute-api.eu-west-1.amazonaws.com.",
		"abc123.execute-api-fips.eu-west-1.amazonaws.com",
		"abc123.execute-api.eu-west-1.api.aws",
		"abc123.execute-api-fips.eu-west-1.api.aws",
	} {
		eg := &fakeEgress{}
		run := newTestRunWith(t, func(c *Config) { c.Egress = eg })
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

func TestAllowAndInstallRefuseIPAddressesAndNamesThatArentPlainASCII(t *testing.T) {
	for _, host := range []string{
		"3.248.245.10", "3.248.245.10.", "127.1", "2130706433", "0x7f.0.0.1", "0x7f000001",
		"[2001:db8::10]", "2001:db8::10",
		"abc\u00ad123.execute-api.eu-west-1.amazonaws.com",
		"abc123\u3002execute-api\u3002eu-west-1\u3002amazonaws\u3002com",
		"\uff41bc123.execute-api.eu-west-1.amazonaws.com",
		"xn--abc123-dja.execute-api.eu-west-1.amazonaws.com",
		"a..example", "example..",
	} {
		eg := &fakeEgress{}
		run := newTestRunWith(t, func(c *Config) { c.Egress = eg })
		if status, _ := run.do(t, "POST", "/allow", map[string]any{"hosts": []string{host}}); status != http.StatusBadRequest {
			t.Errorf("POST /allow %q = %d, want 400", host, status)
		}
		install := map[string]any{"kind": "go", "ref": "example.com/weather@v1.0.0", "allowHosts": []string{host}}
		if status, _ := run.do(t, "POST", "/install", install); status != http.StatusBadRequest {
			t.Errorf("POST /install allowing %q = %d, want 400", host, status)
		}
		if len(eg.allowed) != 0 {
			t.Errorf("allowed %v, want nothing", eg.allowed)
		}
	}
	for _, host := range []string{"api.weather.example", "1password.com", "x.0xdead.io", "123.example"} {
		if err := checkHosts([]string{host}); err != nil {
			t.Errorf("checkHosts(%q) = %v, want a host name", host, err)
		}
	}
}

func TestNewRefusesToStartWithoutTheStacksOwnAPIHost(t *testing.T) {
	for _, host := range []string{"", "api.example.com", "abc123.execute-api.nowhere-1.amazonaws.com"} {
		_, err := New(Config{
			Account: Account{Name: "dev", Home: t.TempDir()}, Workdir: t.TempDir(),
			Installer: &fakeInstaller{}, Now: time.Now, APIHost: host,
		}, slog.New(slog.DiscardHandler))
		if err == nil {
			t.Errorf("New with API host %q started; want it refused", host)
		}
	}
}

// panickingInstaller panics part-way through the install.
type panickingInstaller struct{}

func (panickingInstaller) Install(context.Context, Package, Sandbox) (Installed, error) {
	panic("the installer broke")
}

func TestAPanickingInstallStillEndsTheInstallTimeHosts(t *testing.T) {
	eg := &fakeEgress{}
	run := newIdleRunWith(t, panickingInstaller{}, func(c *Config) { c.Egress = eg })
	if status, body := run.hook(t, "POST", HooksPrefix+"run", runHookRequest(t, testToken, testCanaries)); status != http.StatusOK {
		t.Fatalf("POST /run = %d %s", status, body)
	}
	install := map[string]any{"kind": "go", "ref": "example.com/weather@v1.0.0"}
	func() {
		defer func() { _ = recover() }()
		run.do(t, "POST", "/install", install)
	}()
	if eg.isInstalling() {
		t.Errorf("after the install panicked, the proxy was told %v; want the install ended", eg.installing)
	}
}

func TestBetweenTheInstallAndTheSealOnlyTheRunsAllowlistIsOpen(t *testing.T) {
	for name, inst := range map[string]*fakeInstaller{
		"an install that succeeds": {out: Installed{Command: []string{"weather"}}},
		"an install that fails":    {err: errors.New("the module does not build")},
	} {
		eg := &fakeEgress{}
		run := newTestRunWith(t, func(c *Config) { c.Egress, c.Installer = eg, inst })
		install := map[string]any{"kind": "go", "ref": "example.com/weather@v1.0.0", "allowHosts": []string{"api.weather.example"}}
		if status, body := run.do(t, "POST", "/install", install); status != http.StatusOK && status != http.StatusUnprocessableEntity {
			t.Fatalf("%s: POST /install = %d %v", name, status, body)
		}
		// The install has ended: its hosts are closed before anything else runs.
		if !slices.Equal(eg.installing, []bool{true, false}) {
			t.Errorf("%s: the proxy was told installing %v, want [true false]", name, eg.installing)
		}
		if status, _ := run.do(t, "POST", "/allow", map[string]any{"hosts": []string{"abc123.execute-api-fips.eu-west-1.amazonaws.com"}}); status != http.StatusForbidden {
			t.Errorf("%s: POST /allow of the API before the seal = %d, want 403", name, status)
		}
		if status, _ := run.do(t, "POST", "/allow", map[string]any{"hosts": []string{"collector.example"}}); status != http.StatusOK || !slices.Equal(eg.allowed, []string{"api.weather.example", "collector.example"}) {
			t.Errorf("%s: POST /allow before the seal = %d, allowing %v; want 200 and the run's hosts alone", name, status, eg.allowed)
		}
		if status, _ := run.do(t, "POST", "/seal", map[string]any{}); status != http.StatusOK || eg.seals != 1 || eg.isInstalling() {
			t.Errorf("%s: POST /seal = %d, sealed %d times, installing %v", name, status, eg.seals, eg.isInstalling())
		}
		if status, _ := run.do(t, "POST", "/allow", map[string]any{"hosts": []string{"collector.example"}}); status != http.StatusConflict {
			t.Errorf("%s: POST /allow after the seal = %d, want 409", name, status)
		}
	}
}
