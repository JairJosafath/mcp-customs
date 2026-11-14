package egress

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Bounds on what the proxy reads and waits for.
const (
	// defaultReadTimeout bounds how long the proxy waits for a whole
	// request, body included: a body held open is recorded, as read so
	// far, when it ends.
	defaultReadTimeout = 30 * time.Second
	// maxScan is how much of a request body is searched for canaries.
	maxScan = 8 << 20
	// handshakeTimeout bounds a client's TLS handshake with the proxy.
	handshakeTimeout = 10 * time.Second
	// idleTimeout closes a tunnel the client stopped using.
	idleTimeout = time.Minute
)

// readTimeout is Config.ReadTimeout, or defaultReadTimeout.
func (e *Egress) readTimeout() time.Duration {
	if e.cfg.ReadTimeout > 0 {
		return e.cfg.ReadTimeout
	}
	return defaultReadTimeout
}

// A handshake is the TLS handshake a client sent, as read before the
// tunnel: its records' payloads joined, and whether its ClientHello
// carries an encrypted one (ECH), which can't be searched.
type handshake struct {
	data []byte
	ech  bool
}

// TLS constants readHandshake needs.
const (
	recordHandshake       = 22
	recordHeaderLen       = 5
	msgClientHello        = 1
	extEncryptedHello     = 0xfe0d
	connectRequestEndMark = "\r\n\r\n"
)

// readHandshake reads raw, a CONNECT request and the TLS records the
// client sent after it, for the handshake.
func readHandshake(raw []byte) handshake {
	i := bytes.Index(raw, []byte(connectRequestEndMark))
	if i < 0 {
		return handshake{}
	}
	b := raw[i+len(connectRequestEndMark):]
	var h handshake
	for len(b) >= recordHeaderLen {
		n := int(binary.BigEndian.Uint16(b[3:]))
		if len(b) < recordHeaderLen+n {
			n = len(b) - recordHeaderLen
		}
		if b[0] == recordHandshake {
			h.data = append(h.data, b[recordHeaderLen:recordHeaderLen+n]...)
		}
		b = b[recordHeaderLen+n:]
	}
	h.ech = slices.Contains(helloExtensions(h.data), extEncryptedHello)
	return h
}

// helloExtensions are the extension types of the ClientHello msg starts
// with, as far as it parses.
func helloExtensions(msg []byte) []uint16 {
	if len(msg) < 4 || msg[0] != msgClientHello {
		return nil
	}
	// Type, length, version, random; then the session ID, the cipher
	// suites and the compression methods, each after its length.
	b := msg[min(len(msg), 4+2+32):]
	for _, size := range []int{1, 2, 1} {
		if len(b) < size {
			return nil
		}
		n := int(b[0])
		if size == 2 {
			n = int(binary.BigEndian.Uint16(b))
		}
		if len(b) < size+n {
			return nil
		}
		b = b[size+n:]
	}
	if len(b) < 2 {
		return nil
	}
	b = b[2:]
	var out []uint16
	for len(b) >= 4 {
		out = append(out, binary.BigEndian.Uint16(b))
		n := int(binary.BigEndian.Uint16(b[2:]))
		b = b[min(len(b), 4+n):]
	}
	return out
}

// fakeBody is what a host that isn't allowed answers: a plain success, so
// the server carries on as if its request went through.
const fakeBody = "ok\n"

// Proxy is the HTTP proxy the server's HTTPS_PROXY and HTTP_PROXY name. It
// intercepts CONNECT tunnels with the CA and serves plain proxied requests.
func (e *Egress) Proxy() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodConnect {
			if e.isSealed() {
				e.refuseSealed(w, r)
				return
			}
			e.tunnel(w, r)
			return
		}
		if r.URL.Host == "" {
			e.recordNotProxied(r)
			http.Error(w, "not a proxy request", http.StatusBadRequest)
			return
		}
		e.forward(w, r, "http", r.URL.Host)
	})
}

// tunnel answers a CONNECT: it takes the connection, shows the client a
// certificate for the host signed by the CA, and serves the requests inside
// as if it were the host.
func (e *Egress) tunnel(w http.ResponseWriter, r *http.Request) {
	host, port := splitHostPort(r.Host, 443)
	// The CONNECT request is searched, as is everything the client sends
	// in the clear before the tunnel is read: its TLS handshake.
	var seen bytes.Buffer
	seen.WriteString(r.Host + "\n")
	_ = r.Header.Write(&seen)
	rc := rawConnOf(r.Context())
	conn, _, err := http.NewResponseController(w).Hijack()
	if err != nil {
		http.Error(w, "cannot tunnel", http.StatusInternalServerError)
		return
	}
	defer func() { _ = conn.Close() }()
	// The server's read deadline was for the CONNECT request; the tunnel
	// keeps its own.
	_ = conn.SetDeadline(time.Time{})
	if _, err := io.WriteString(conn, "HTTP/1.1 200 Connection established\r\n\r\n"); err != nil {
		return
	}
	var serverName string
	tlsConn := tls.Server(conn, &tls.Config{
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"http/1.1"},
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			serverName = hello.ServerName
			if hello.ServerName != "" {
				return e.cfg.CA.leaf(hello.ServerName)
			}
			return e.cfg.CA.leaf(host)
		},
	})
	ctx, cancel := context.WithTimeout(r.Context(), handshakeTimeout)
	err = tlsConn.HandshakeContext(ctx)
	cancel()
	// The ClientHello is sent in the clear, so a key may ride in any of
	// it (the server name, ALPN, the session ID, an unknown extension): the
	// handshake as sent is searched, its records joined, and the server
	// name with its dots taken out.
	seen.WriteString(serverName + "\n" + strings.ReplaceAll(serverName, ".", "") + "\n")
	var hello handshake
	if rc != nil {
		raw := rc.handOff()
		hello = readHandshake(raw)
		seen.Write(raw)
		seen.Write(hello.data)
	}
	d := ConnectDetail{Host: host, ServerName: serverName, Port: port, Via: "proxy", Intercepted: err == nil, Allowed: e.isAllowed(host)}
	if found := e.match(seen.Bytes()); len(found) > 0 {
		d.Canaries = found
	}
	if hello.ech {
		d.Unscanned = "the ClientHello carries an encrypted ClientHello, which can't be searched"
	}
	e.record(KindConnect, d)
	if err != nil {
		return
	}
	inner := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			e.forward(w, r, "https", r.Host)
		}),
		ReadHeaderTimeout: handshakeTimeout,
		ReadTimeout:       e.readTimeout(),
		IdleTimeout:       idleTimeout,
		ConnContext:       withRawConn,
	}
	_ = inner.Serve(newOneConnListener(e.newRawConn(tlsConn, host)))
}

// forward records one request, searched for canaries, then sends it on to
// an allowed host or answers it with a fake 200.
func (e *Egress) forward(w http.ResponseWriter, r *http.Request, scheme, hostport string) {
	host, port := splitHostPort(hostport, 0)
	head, body, more, readErr := readScanned(r.Body)
	var seen bytes.Buffer
	_ = r.Header.Write(&seen)
	seen.WriteString(r.Method + " " + r.URL.RequestURI() + "\n")
	seen.Write(head)
	// The body was read to its end, so a chunked body's trailer is in.
	_ = r.Trailer.Write(&seen)
	decoded, unscanned := decodeBody(r.Header.Values("Content-Encoding"), head)
	seen.Write(decoded)
	if more {
		unscanned = fmt.Sprintf("the body is over %d MiB; only its first %d MiB were searched", maxScan>>20, maxScan>>20)
	}
	// What was sent for this request, as sent: chunk extensions, which the
	// parser drops, and a body cut short or malformed.
	if rc := rawConnOf(r.Context()); rc != nil {
		raw, over := rc.take()
		seen.Write(raw)
		if over && unscanned == "" {
			unscanned = fmt.Sprintf("the request is over %d MiB as sent; only its first %d MiB were searched as sent", maxScan>>20, maxScan>>20)
		}
	}
	if readErr != nil {
		unscanned = "the body could not be read whole; what was read was searched"
	}
	target, err := upstreamURL(scheme, host, port, r.URL)
	allowed := e.isAllowed(host) && err == nil && readErr == nil
	e.record(KindHTTP, HTTPDetail{
		Method:    r.Method,
		Host:      host,
		Path:      r.URL.Path,
		Allowed:   allowed,
		Canaries:  e.match(seen.Bytes()),
		Unscanned: unscanned,
	})
	if readErr != nil {
		http.Error(w, "cannot read the request", http.StatusBadRequest)
		return
	}
	if !allowed {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = io.WriteString(w, fakeBody)
		return
	}
	e.pass(w, r, target, body)
}

// recordNotProxied records a request sent to the proxy as if it were the
// host, which goes nowhere: what was sent for it is searched as sent.
func (e *Egress) recordNotProxied(r *http.Request) {
	var seen bytes.Buffer
	_ = r.Header.Write(&seen)
	seen.WriteString(r.Method + " " + r.URL.RequestURI() + "\n")
	var unscanned string
	if rc := rawConnOf(r.Context()); rc != nil {
		n, err := io.Copy(io.Discard, io.LimitReader(r.Body, maxScan+1))
		raw, over := rc.take()
		seen.Write(raw)
		switch {
		case n > maxScan || over:
			unscanned = fmt.Sprintf("the request is over %d MiB; only its first %d MiB were searched", maxScan>>20, maxScan>>20)
		case err != nil:
			unscanned = "the body could not be read whole; what was read was searched"
		}
	}
	e.record(KindHTTP, HTTPDetail{Method: r.Method, Host: normalHost(r.Host), Path: r.URL.Path, Canaries: e.match(seen.Bytes()), Unscanned: unscanned})
}

// upstreamURL is where an allowed request goes: built from the host and
// port the proxy checked, never from the raw Host header.
func upstreamURL(scheme, host string, port int, u *url.URL) (string, error) {
	if host == "" || strings.ContainsAny(host, "@/?#[] ") {
		return "", fmt.Errorf("%q is not a host", host)
	}
	hostport := host
	if port != 0 {
		hostport = net.JoinHostPort(host, strconv.Itoa(port))
	}
	out := url.URL{Scheme: scheme, Host: hostport, Path: u.Path, RawPath: u.RawPath, RawQuery: u.RawQuery}
	return out.String(), nil
}

// pass sends r on to target and copies the answer back.
func (e *Egress) pass(w http.ResponseWriter, r *http.Request, target string, body io.Reader) {
	ctx, stop := e.untilSealed(r.Context())
	defer stop()
	out, err := http.NewRequestWithContext(ctx, r.Method, target, body) //nolint:gosec // only hosts on the run's allowlist are reached; forward checks it first
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	out.Header = r.Header.Clone()
	for _, h := range hopHeaders {
		out.Header.Del(h)
	}
	out.ContentLength = r.ContentLength
	resp, err := e.cfg.Upstream.RoundTrip(out)
	if err != nil {
		http.Error(w, "upstream unreachable", http.StatusBadGateway)
		return
	}
	defer func() { _ = resp.Body.Close() }()
	for k, vs := range resp.Header {
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	for _, h := range hopHeaders {
		w.Header().Del(h)
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

// hopHeaders are a connection's own headers, not sent on.
var hopHeaders = []string{
	"Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate",
	"Proxy-Authorization", "Te", "Trailer", "Transfer-Encoding", "Upgrade",
}

// readScanned reads up to maxScan bytes of body for searching, and returns
// them with a reader of the whole body, and whether there was more. When
// the read fails, it returns what it read before.
func readScanned(body io.Reader) ([]byte, io.Reader, bool, error) {
	if body == nil {
		return nil, http.NoBody, false, nil
	}
	head, err := io.ReadAll(io.LimitReader(body, maxScan+1))
	if err != nil {
		return head, nil, false, fmt.Errorf("read the body: %w", err)
	}
	more := len(head) > maxScan
	return head[:min(len(head), maxScan)], io.MultiReader(bytes.NewReader(head), body), more, nil
}

// maxCodings bounds how many content codings one body is decoded through.
const maxCodings = 4

// decodeBody is head decoded through every coding the Content-Encoding
// header lines name (values), last applied first, up to maxScan bytes, for
// searching; and why some of it went unsearched, if it did.
func decodeBody(values []string, head []byte) ([]byte, string) {
	var codings []string
	for _, v := range values {
		for c := range strings.SplitSeq(v, ",") {
			if c = strings.ToLower(strings.TrimSpace(c)); c != "" && c != "identity" {
				codings = append(codings, c)
			}
		}
	}
	if len(codings) == 0 {
		return nil, ""
	}
	if len(codings) > maxCodings {
		return nil, fmt.Sprintf("the body is encoded %d times; at most %d are decoded", len(codings), maxCodings)
	}
	data := head
	for i := len(codings) - 1; i >= 0; i-- {
		out, why := decodeOnce(codings[i], data)
		if why != "" {
			return out, why
		}
		data = out
	}
	return data, ""
}

// decodeOnce is data decoded from one content coding, up to maxScan bytes,
// and why it isn't whole, if it isn't.
func decodeOnce(coding string, data []byte) ([]byte, string) {
	var r io.Reader
	switch coding {
	case "gzip", "x-gzip":
		gz, err := gzip.NewReader(bytes.NewReader(data))
		if err != nil {
			return nil, "the gzip body could not be decoded"
		}
		r = gz
	case "deflate":
		// HTTP's deflate is zlib-wrapped; some clients send it raw.
		if z, err := zlib.NewReader(bytes.NewReader(data)); err == nil {
			r = z
		} else {
			r = flate.NewReader(bytes.NewReader(data))
		}
	default:
		return nil, fmt.Sprintf("the body's encoding %q can't be decoded", coding)
	}
	out, err := io.ReadAll(io.LimitReader(r, maxScan+1))
	switch {
	case len(out) > maxScan:
		return out[:maxScan], fmt.Sprintf("the decoded body is over %d MiB; only its first %d MiB were searched", maxScan>>20, maxScan>>20)
	case err != nil && !errors.Is(err, io.ErrUnexpectedEOF):
		return out, "the " + coding + " body could not be decoded whole"
	case err != nil:
		return out, "the " + coding + " body is cut short; what decoded was searched"
	}
	return out, ""
}

// splitHostPort splits "host:port", giving port def when there is none. A
// port that isn't one leaves the whole string as the host, which no
// allowlist names: "pypi.org:443.evil.example" is not pypi.org.
func splitHostPort(hostport string, def int) (string, int) {
	host, p, err := net.SplitHostPort(hostport)
	if err != nil {
		return normalHost(hostport), def
	}
	port, err := strconv.Atoi(p)
	if err != nil || port < 1 || port > 65535 {
		return normalHost(hostport), def
	}
	return normalHost(host), port
}

// oneConnListener hands out one connection, then waits until it is closed,
// so an http.Server serves exactly that connection.
type oneConnListener struct {
	conn   net.Conn
	once   sync.Once
	served bool
	closed chan struct{}
}

func newOneConnListener(c net.Conn) *oneConnListener {
	l := &oneConnListener{closed: make(chan struct{})}
	l.conn = &closeNotifier{Conn: c, onClose: l.closeOnce}
	return l
}

var errListenerDone = errors.New("the connection is closed")

func (l *oneConnListener) Accept() (net.Conn, error) {
	if !l.served {
		l.served = true
		return l.conn, nil
	}
	<-l.closed
	return nil, errListenerDone
}

func (l *oneConnListener) Close() error {
	l.closeOnce()
	return nil
}

func (l *oneConnListener) closeOnce() {
	l.once.Do(func() { close(l.closed) })
}

func (l *oneConnListener) Addr() net.Addr {
	return l.conn.LocalAddr()
}

// closeNotifier tells its listener when the connection closes.
type closeNotifier struct {
	net.Conn
	onClose func()
}

func (c *closeNotifier) Close() error {
	err := c.Conn.Close()
	c.onClose()
	return err
}
