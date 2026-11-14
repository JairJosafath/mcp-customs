package egress

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Bounds on what the proxy reads and waits for.
const (
	// maxScan is how much of a request body is searched for canaries.
	maxScan = 8 << 20
	// handshakeTimeout bounds a client's TLS handshake with the proxy.
	handshakeTimeout = 10 * time.Second
	// idleTimeout closes a tunnel the client stopped using.
	idleTimeout = time.Minute
)

// fakeBody is what a host that isn't allowed answers: a plain success, so
// the server carries on as if its request went through.
const fakeBody = "ok\n"

// Proxy is the HTTP proxy the server's HTTPS_PROXY and HTTP_PROXY name. It
// intercepts CONNECT tunnels with the CA and serves plain proxied requests.
func (e *Egress) Proxy() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodConnect {
			e.tunnel(w, r)
			return
		}
		if r.URL.Host == "" {
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
	conn, _, err := http.NewResponseController(w).Hijack()
	if err != nil {
		http.Error(w, "cannot tunnel", http.StatusInternalServerError)
		return
	}
	defer func() { _ = conn.Close() }()
	if _, err := io.WriteString(conn, "HTTP/1.1 200 Connection established\r\n\r\n"); err != nil {
		return
	}
	tlsConn := tls.Server(conn, &tls.Config{
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"http/1.1"},
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			if hello.ServerName != "" {
				return e.cfg.CA.leaf(hello.ServerName)
			}
			return e.cfg.CA.leaf(host)
		},
	})
	ctx, cancel := context.WithTimeout(r.Context(), handshakeTimeout)
	err = tlsConn.HandshakeContext(ctx)
	cancel()
	e.record(KindConnect, ConnectDetail{Host: host, Port: port, Via: "proxy", Intercepted: err == nil, Allowed: e.isAllowed(host)})
	if err != nil {
		return
	}
	inner := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			e.forward(w, r, "https", r.Host)
		}),
		ReadHeaderTimeout: handshakeTimeout,
		IdleTimeout:       idleTimeout,
	}
	_ = inner.Serve(newOneConnListener(tlsConn))
}

// forward records one request, searched for canaries, then sends it on to
// an allowed host or answers it with a fake 200.
func (e *Egress) forward(w http.ResponseWriter, r *http.Request, scheme, hostport string) {
	host, port := splitHostPort(hostport, 0)
	head, body, more, err := readScanned(r.Body)
	if err != nil {
		http.Error(w, "cannot read the request", http.StatusBadRequest)
		return
	}
	var seen bytes.Buffer
	_ = r.Header.Write(&seen)
	seen.WriteString(r.Method + " " + r.URL.RequestURI() + "\n")
	seen.Write(head)
	decoded, unscanned := decodeBody(r.Header.Get("Content-Encoding"), head)
	seen.Write(decoded)
	if more {
		unscanned = fmt.Sprintf("the body is over %d MiB; only its first %d MiB were searched", maxScan>>20, maxScan>>20)
	}
	target, err := upstreamURL(scheme, host, port, r.URL)
	allowed := e.isAllowed(host) && err == nil
	e.record(KindHTTP, HTTPDetail{
		Method:    r.Method,
		Host:      host,
		Path:      r.URL.Path,
		Allowed:   allowed,
		Canaries:  e.match(seen.Bytes()),
		Unscanned: unscanned,
	})
	if !allowed {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = io.WriteString(w, fakeBody)
		return
	}
	e.pass(w, r, target, body)
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
	out, err := http.NewRequestWithContext(r.Context(), r.Method, target, body) //nolint:gosec // only hosts on the run's allowlist are reached; forward checks it first
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
// them with a reader of the whole body, and whether there was more.
func readScanned(body io.Reader) ([]byte, io.Reader, bool, error) {
	if body == nil {
		return nil, http.NoBody, false, nil
	}
	head, err := io.ReadAll(io.LimitReader(body, maxScan+1))
	if err != nil {
		return nil, nil, false, fmt.Errorf("read the body: %w", err)
	}
	more := len(head) > maxScan
	return head[:min(len(head), maxScan)], io.MultiReader(bytes.NewReader(head), body), more, nil
}

// decodeBody is head decoded as encoding says, up to maxScan bytes, for
// searching, and why some of it went unsearched, if it did.
func decodeBody(encoding string, head []byte) ([]byte, string) {
	var r io.Reader
	switch e := strings.ToLower(strings.TrimSpace(encoding)); e {
	case "", "identity":
		return nil, ""
	case "gzip", "x-gzip":
		gz, err := gzip.NewReader(bytes.NewReader(head))
		if err != nil {
			return nil, "the gzip body could not be decoded"
		}
		r = gz
	case "deflate":
		// HTTP's deflate is zlib-wrapped; some clients send it raw.
		if z, err := zlib.NewReader(bytes.NewReader(head)); err == nil {
			r = z
		} else {
			r = flate.NewReader(bytes.NewReader(head))
		}
	default:
		return nil, fmt.Sprintf("the body's encoding %q can't be decoded", e)
	}
	out, err := io.ReadAll(io.LimitReader(r, maxScan+1))
	switch {
	case len(out) > maxScan:
		return out[:maxScan], fmt.Sprintf("the decoded body is over %d MiB; only its first %d MiB were searched", maxScan>>20, maxScan>>20)
	case err != nil && !errors.Is(err, io.ErrUnexpectedEOF):
		return out, "the " + encoding + " body could not be decoded whole"
	case err != nil:
		return out, "the " + encoding + " body is cut short; what decoded was searched"
	}
	return out, ""
}

// splitHostPort splits "host:port", giving port def when there is none.
func splitHostPort(hostport string, def int) (string, int) {
	host, p, err := net.SplitHostPort(hostport)
	if err != nil {
		return normalHost(hostport), def
	}
	port, err := strconv.Atoi(p)
	if err != nil {
		port = def
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
