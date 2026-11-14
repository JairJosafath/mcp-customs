package harness

import (
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

// mailSinkHost is the fixed host src/demo/mail v1.0.1 blind-copies every
// message to; it matches the sinkHost constant in that build.
const mailSinkHost = "mail-sink.example"

// TestTheMailDemosRugPullCopiesTheRecipientToAnOutsideSink runs the real
// src/demo/mail built with -tags v1_0_1 as an unprivileged user behind the
// real firewall, calls send_email with the planted canary address as the
// recipient, and finds that address leaving to the fixed sink host, which
// the proxy faked and denied. This is the rug pull of docs/plan.md, end to
// end: it needs root to redirect the demo's traffic and run it as another
// user, so it skips otherwise, as the weather e2e does.
func TestTheMailDemosRugPullCopiesTheRecipientToAnOutsideSink(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to redirect the demo's traffic with iptables and run it as another user: run `go test` as root to run it")
	}
	if err := egress.Exec(t.Context(), egress.Command{"iptables", "-w", "-t", "nat", "-L", "OUTPUT", "-n"}); err != nil {
		t.Skipf("needs iptables and CAP_NET_ADMIN: %v", err)
	}
	base := sharedDir(t)
	mail := buildMail(t, base)
	home := filepath.Join(base, "home")
	if err := os.Mkdir(home, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(home, e2eUID, e2eUID); err != nil {
		t.Fatal(err)
	}
	eg, l := startEgress(t, filepath.Join(base, "trust"), net.DefaultResolver)
	upFirewall(t, eg, l)

	inst := &fakeInstaller{out: Installed{Resolved: []byte("mod mail\n"), Command: []string{mail}}}
	run := newIdleRunWith(t, inst, func(c *Config) {
		c.Account = Account{Name: "e2e", Home: home, UID: e2eUID, GID: e2eUID, Switch: true}
		c.Workdir = filepath.Join(home, "projects", "server")
		c.Path = "/usr/local/bin:/usr/bin:/bin"
		c.Egress = eg
	})
	run.home = home
	set := canary.New()
	canaries := []Canary{}
	for _, c := range set {
		canaries = append(canaries, Canary{Kind: CanaryKind(c.Kind), Value: c.Value})
	}
	if status, body := run.hook(t, http.MethodPost, HooksPrefix+"run", runHookRequest(t, testToken, canaries)); status != http.StatusOK {
		t.Fatalf("POST /run = %d %s", status, body)
	}
	if status, body := run.do(t, http.MethodPost, "/install", installBody("go", "github.com/JairJosafath/mcp-customs/src/demo/mail@v1.0.1")); status != http.StatusOK {
		t.Fatalf("POST /install = %d %v", status, body)
	}
	if status, body := run.do(t, http.MethodPost, "/start", nil); status != http.StatusOK {
		t.Fatalf("POST /start = %d %v", status, body)
	}

	// The probe a model would write: the planted canary address as the
	// recipient. v1.0.1 copies the whole message, that address included.
	victim := set.Get(canary.Email)
	body := call(t, run, "send_email", map[string]string{"to": victim, "subject": "Quarterly numbers", "body": "Attached."})
	if got := toolText(t, body); got != "sent" {
		t.Errorf("send_email = %q, want the clean \"sent\" a rug pull hides behind", got)
	}
	obs := observations(t, body)

	requests := decoded[egress.HTTPDetail](t, obs, ObservedHTTP)
	if !slices.ContainsFunc(requests, func(d egress.HTTPDetail) bool {
		return d.Host == mailSinkHost && d.Method == http.MethodPost && !d.Allowed &&
			slices.Contains(d.Canaries, findings.Match{Canary: canary.Email, Encoding: findings.Plain})
	}) {
		t.Errorf("http observations = %+v, want a POST to %s carrying the canary address", requests, mailSinkHost)
	}
	t.Logf("the recipient left for %s, seen as %+v", mailSinkHost, requests)
}

// buildMail builds src/demo/mail with the v1_0_1 build tag into dir,
// statically, so it uses Go's own resolver like the sandbox's servers.
func buildMail(t *testing.T, dir string) string {
	t.Helper()
	out := filepath.Join(dir, "mail")
	cmd := exec.CommandContext(t.Context(), "go", "build", "-tags", "v1_0_1", "-o", out, "../../demo/mail") //nolint:gosec // building the repository's own demo into the test's directory
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	if msg, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build the mail demo: %v\n%s", err, msg)
	}
	return out
}
