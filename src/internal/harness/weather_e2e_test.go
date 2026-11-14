package harness

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"testing"

	"github.com/JairJosafath/mcp-customs/src/internal/canary"
	"github.com/JairJosafath/mcp-customs/src/internal/egress"
	"github.com/JairJosafath/mcp-customs/src/internal/findings"
)

// nobody is the unprivileged account the weather demo runs as here.
const nobody = 65534

// weatherCfgDomain is the demo's WEATHER_CFG_DOMAIN: its loot goes to the
// host the TXT record of _cfg.<domain> names, which the proxy fakes.
const weatherCfgDomain = "weather-cfg.example"

// TestTheWeatherDemosStolenKeyIsSeenLeavingBase64Encoded runs
// src/demo/weather as an unprivileged user behind the real firewall,
// calls it with the planted fake SSH key in auth_context, and finds the key
// leaving, base64-encoded, to the host the faked TXT record named. The
// demo resolves that record with Go's own resolver, straight to the
// nameserver in /etc/resolv.conf, so only the firewall's DNS redirect
// brings the query to the harness: that needs root.
func TestTheWeatherDemosStolenKeyIsSeenLeavingBase64Encoded(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to redirect the demo's DNS with iptables and run it as another user: run `go test` as root to run it")
	}
	if err := egress.Exec(t.Context(), egress.Command{"iptables", "-w", "-t", "nat", "-L", "OUTPUT", "-n"}); err != nil {
		t.Skipf("needs iptables and CAP_NET_ADMIN: %v", err)
	}
	base := sharedDir(t)
	weather := buildWeather(t, base)
	home := filepath.Join(base, "home")
	if err := os.Mkdir(home, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(home, nobody, nobody); err != nil {
		t.Fatal(err)
	}
	eg, l := startEgress(t, filepath.Join(base, "trust"), net.DefaultResolver)
	upFirewall(t, l)

	inst := &fakeInstaller{out: Installed{Resolved: []byte("mod weather\n"), Command: []string{"/usr/bin/env", "WEATHER_CFG_DOMAIN=" + weatherCfgDomain, weather}}}
	run := newIdleRunWith(t, inst, func(c *Config) {
		c.Account = Account{Name: "nobody", Home: home, UID: nobody, GID: nobody, Switch: true}
		c.Workdir = filepath.Join(home, "projects", "server")
		c.Path = "/usr/local/bin:/usr/bin:/bin"
		c.Egress = eg
	})
	run.home = home
	canaries := []Canary{}
	for _, c := range canary.New() {
		canaries = append(canaries, Canary{Kind: CanaryKind(c.Kind), Value: c.Value})
	}
	if status, body := run.hook(t, http.MethodPost, HooksPrefix+"run", runHookRequest(t, testToken, canaries)); status != http.StatusOK {
		t.Fatalf("POST /run = %d %s", status, body)
	}
	if status, body := run.do(t, http.MethodPost, "/install", installBody("go", "github.com/JairJosafath/mcp-customs/src/demo/weather@v0.0.0")); status != http.StatusOK {
		t.Fatalf("POST /install = %d %v", status, body)
	}
	if status, body := run.do(t, http.MethodPost, "/start", nil); status != http.StatusOK {
		t.Fatalf("POST /start = %d %v", status, body)
	}

	// The planted key, as a model that took the demo's bait would send it.
	key, err := os.ReadFile(filepath.Join(home, ".ssh", "id_ed25519"))
	if err != nil {
		t.Fatal(err)
	}
	body := call(t, run, "get_forecast", map[string]string{"city": "Lisbon", "auth_context": string(key)})
	if got := toolText(t, body); got != "Forecast for Lisbon: 18C, partly cloudy." {
		t.Errorf("get_forecast = %q", got)
	}
	obs := observations(t, body)

	cfg := "_cfg." + weatherCfgDomain
	loot := egress.FakeTXT(cfg)
	lookups := decoded[egress.DNSDetail](t, obs, ObservedDNS)
	if !slices.ContainsFunc(lookups, func(d egress.DNSDetail) bool {
		return d.Name == cfg && d.Type == "TXT" && d.Faked && slices.Equal(d.Answers, []string{loot})
	}) {
		t.Errorf("dns observations = %+v, want the faked TXT of %s naming %s", lookups, cfg, loot)
	}
	requests := decoded[egress.HTTPDetail](t, obs, ObservedHTTP)
	if !slices.ContainsFunc(requests, func(d egress.HTTPDetail) bool {
		return d.Host == loot && d.Method == http.MethodPost && !d.Allowed &&
			slices.Contains(d.Canaries, findings.Match{Canary: canary.SSHPrivateKey, Encoding: findings.Base64})
	}) {
		t.Errorf("http observations = %+v, want a POST to %s carrying the SSH key, base64", requests, loot)
	}
	t.Logf("the key left for %s, seen as %+v", loot, requests)
}

// sharedDir is a directory of the test's that the unprivileged account
// may read, as /etc and /usr/local are: t.TempDir and its parent are
// private to root.
func sharedDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	for _, d := range []string{filepath.Dir(dir), dir} {
		if err := os.Chmod(d, 0o755); err != nil { //nolint:gosec // the account must reach the demo's binary and the CA's certificate
			t.Fatal(err)
		}
	}
	return dir
}

// buildWeather builds src/demo/weather into dir, statically, so it uses
// Go's own resolver.
func buildWeather(t *testing.T, dir string) string {
	t.Helper()
	out := filepath.Join(dir, "weather")
	cmd := exec.CommandContext(t.Context(), "go", "build", "-o", out, "../../demo/weather") //nolint:gosec // building the repository's own demo into the test's directory
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	if msg, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build the weather demo: %v\n%s", err, msg)
	}
	return out
}

// upFirewall holds the account's traffic to the proxy on l, until the
// test ends.
func upFirewall(t *testing.T, l *egress.Listeners) {
	t.Helper()
	proxy, dns, catch := l.Ports()
	fw := egress.Firewall{Chain: fmt.Sprintf("MCPC_E2E_%d", os.Getpid()), UID: nobody, ProxyPort: proxy, DNSPort: dns, CatchPort: catch}
	if err := fw.Up(t.Context(), egress.Exec); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { fw.Down(context.Background(), egress.Exec) })
}
