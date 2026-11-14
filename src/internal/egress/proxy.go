package egress

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
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
	e.record(KindConnect, ConnectDetail{Host: host, Port: port, Via: "proxy", Intercepted: err == nil})
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
	host, _ := splitHostPort(hostport, 0)
	head, body, err := readScanned(r.Body)
	if err != nil {
		http.Error(w, "cannot read the request", http.StatusBadRequest)
		return
	}
	var seen bytes.Buffer
	_ = r.Header.Write(&seen)
	seen.WriteString(r.Method + " " + r.URL.RequestURI() + "\n")
	seen.Write(head)
	allowed := e.isAllowed(host)
	e.record(KindHTTP, HTTPDetail{
		Method:   r.Method,
		Host:     host,
		Path:     r.URL.Path,
		Allowed:  allowed,
		Canaries: e.match(seen.Bytes()),
	})
	if !allowed {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = io.WriteString(w, fakeBody)
		return
	}
	e.pass(w, r, scheme, hostport, body)
}

// pass sends r on to its real host and copies the answer back.
func (e *Egress) pass(w http.ResponseWriter, r *http.Request, scheme, hostport string, body io.Reader) {
	out, err := http.NewRequestWithContext(r.Context(), r.Method, scheme+"://"+hostport+r.URL.RequestURI(), body) //nolint:gosec // only hosts on the run's allowlist are reached; forward checks it first
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
// them with a reader of the whole body.
func readScanned(body io.Reader) ([]byte, io.Reader, error) {
	if body == nil {
		return nil, http.NoBody, nil
	}
	head, err := io.ReadAll(io.LimitReader(body, maxScan))
	if err != nil {
		return nil, nil, fmt.Errorf("read the body: %w", err)
	}
	return head, io.MultiReader(bytes.NewReader(head), body), nil
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
