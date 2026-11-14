package egress

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
)

// nobody is the unprivileged account the root-only tests run clients as.
const nobody = 65534

// requireFirewall skips a test that puts up the real firewall unless it
// runs as root with iptables and CAP_NET_ADMIN, as the harness does in
// the MicroVM.
func requireFirewall(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("needs root to put up the firewall with iptables: run `go test` as root to run it")
	}
	if err := Exec(t.Context(), Command{"iptables", "-w", "-t", "nat", "-L", "OUTPUT", "-n"}); err != nil {
		t.Skipf("needs iptables and CAP_NET_ADMIN: %v", err)
	}
}

// asNobody runs a shell script as the unprivileged account, as the
// harness runs the server under test, and answers its output.
func asNobody(t *testing.T, script string) (string, error) {
	t.Helper()
	id := strconv.Itoa(nobody)
	args := []string{"--reuid=" + id, "--regid=" + id, "--clear-groups", "--no-new-privs", "--", "/bin/bash", "-c", script}
	cmd := exec.CommandContext(t.Context(), "/usr/bin/setpriv", args...) //nolint:gosec // the tests' own scripts, run as an unprivileged user
	cmd.Env = []string{"PATH=/usr/bin:/bin", "HOME=/"}
	cmd.Dir = "/"
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// upFirewall serves e and holds nobody's traffic to it, until the test ends.
func upFirewall(t *testing.T, e *Egress) {
	t.Helper()
	l, err := Listen(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	stop := e.Serve(l, RedirectedFrom)
	t.Cleanup(stop)
	proxy, dns, catch := l.Ports()
	fw := Firewall{Chain: fmt.Sprintf("MCPC_TEST_%d", os.Getpid()), UID: nobody, ProxyPort: proxy, DNSPort: dns, CatchPort: catch}
	if err := fw.Up(t.Context(), Exec); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { fw.Down(context.Background(), Exec) })
}

func TestADirectConnectionToAnOutsideAddressIsRefusedAndRecorded(t *testing.T) {
	requireFirewall(t)
	rec := newRecorded()
	e := New(Config{CA: newCA(t), Upstream: &fakeUpstream{}, Resolver: fakeResolver{}})
	e.Observe(rec.observe)
	upFirewall(t, e)

	// 203.0.113.7 (TEST-NET-3) on 443, ignoring HTTPS_PROXY: as a pinned
	// client or raw socket would. Whatever the far end says is printed.
	out, err := asNobody(t, `exec 3<>/dev/tcp/203.0.113.7/443 || exit 7
printf 'GET / HTTP/1.0\r\nHost: 203.0.113.7\r\n\r\n' >&3
cat <&3`)
	if err == nil || strings.Contains(out, "HTTP/") {
		t.Errorf("the direct connection = %q, %v; want it refused, nothing answered", out, err)
	}
	// The catcher records a connection before it resets it, so it is
	// recorded by the time the client has seen the reset.
	want := ConnectDetail{Address: "203.0.113.7", Port: 443, Via: "direct", Refused: true}
	if got := rec.of(KindConnect); len(got) != 1 || got[0] != want {
		t.Errorf("connect = %+v, want %+v", got, want)
	}

	// UDP anywhere but DNS, and IPv6, are rejected outright.
	if out, err := asNobody(t, `echo x > /dev/udp/203.0.113.7/123`); err == nil {
		t.Errorf("direct UDP = %q, want it rejected", out)
	}
}

func TestTheCAKeyIsOutOfTheServersReach(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root, as the harness runs, to show another user can't reach the CA: run `go test` as root to run it")
	}
	base := sharedTempDir(t)
	dir := filepath.Join(base, "mcp-customs")
	trust, err := WriteTrust(dir, newCA(t), nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{dir, trust.CAFile, trust.BundleFile} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		st, _ := info.Sys().(*syscall.Stat_t)
		if st == nil || st.Uid != 0 || info.Mode().Perm()&0o022 != 0 {
			t.Errorf("%s is %v, owned by %v; want root's, writable by root alone", path, info.Mode(), st)
		}
	}
	// The certificate is the server's to read; the key is nowhere it can
	// read: not on disk, and not in the harness's memory or environment,
	// which only root may read of a root process.
	pid := strconv.Itoa(os.Getpid())
	if out, err := asNobody(t, "cat "+trust.CAFile); err != nil || !strings.Contains(out, "BEGIN CERTIFICATE") {
		t.Errorf("the server can't read the CA's certificate: %q, %v", out, err)
	}
	if out, err := asNobody(t, "grep -rl 'PRIVATE KEY' "+dir); err == nil {
		t.Errorf("a private key is in the trust directory: %q", out)
	}
	for _, f := range []string{"mem", "maps", "environ"} {
		if out, err := asNobody(t, "head -c 64 /proc/"+pid+"/"+f+" | od -c | head -1"+"; exit ${PIPESTATUS[0]}"); err == nil {
			t.Errorf("the server can read the harness's /proc/%s/%s: %q", pid, f, out)
		}
	}
	if out, err := asNobody(t, "echo forged > "+trust.CAFile+" || touch "+filepath.Join(dir, "planted")); err == nil {
		t.Errorf("the server can change what it trusts: %q", out)
	}
}

// sharedTempDir is a directory of the test's that the unprivileged account
// may read, as /etc is: t.TempDir and its parent are private to root.
func sharedTempDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	for _, d := range []string{filepath.Dir(dir), dir} {
		if err := os.Chmod(d, 0o755); err != nil { //nolint:gosec // the account must read what the test puts here
			t.Fatal(err)
		}
	}
	return dir
}
