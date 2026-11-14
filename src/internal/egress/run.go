package egress

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"
)

// Listeners are where the proxy, DNS and the catcher of direct connections
// listen, all on 127.0.0.1.
type Listeners struct {
	Proxy net.Listener
	DNS   net.PacketConn
	Catch net.Listener
}

// Listen opens the listeners on free ports of 127.0.0.1.
func Listen(ctx context.Context) (*Listeners, error) {
	var lc net.ListenConfig
	proxy, err := lc.Listen(ctx, "tcp4", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("listen for the proxy: %w", err)
	}
	dns, err := lc.ListenPacket(ctx, "udp4", "127.0.0.1:0")
	if err != nil {
		_ = proxy.Close()
		return nil, fmt.Errorf("listen for DNS: %w", err)
	}
	catch, err := lc.Listen(ctx, "tcp4", "127.0.0.1:0")
	if err != nil {
		_ = proxy.Close()
		_ = dns.Close()
		return nil, fmt.Errorf("listen for direct connections: %w", err)
	}
	return &Listeners{Proxy: proxy, DNS: dns, Catch: catch}, nil
}

// Ports are the listeners' ports, for the firewall.
func (l *Listeners) Ports() (proxy, dns, catch int) {
	return port(l.Proxy.Addr()), port(l.DNS.LocalAddr()), port(l.Catch.Addr())
}

func port(a net.Addr) int {
	_, p, err := net.SplitHostPort(a.String())
	if err != nil {
		return 0
	}
	n, _ := strconv.Atoi(p)
	return n
}

// Serve serves the proxy, DNS and the catcher on l until stop is called,
// which closes them and waits for them to end.
func (e *Egress) Serve(l *Listeners, dst OriginalDestination) (stop func()) {
	srv := &http.Server{Handler: e.Proxy(), ReadHeaderTimeout: handshakeTimeout, IdleTimeout: idleTimeout}
	var wg sync.WaitGroup
	wg.Go(func() { _ = srv.Serve(l.Proxy) })
	wg.Go(func() { _ = e.ServeDNS(l.DNS) })
	wg.Go(func() { _ = e.ServeCatch(l.Catch, dst) })
	return func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := srv.Shutdown(ctx); err != nil {
			_ = srv.Close()
		}
		_ = l.DNS.Close()
		_ = l.Catch.Close()
		wg.Wait()
	}
}

// Trust is where the files the server trusts the CA through are.
type Trust struct {
	// CAFile holds only the CA's certificate.
	CAFile string
	// BundleFile holds the system's roots and the CA's certificate.
	BundleFile string
}

// WriteTrust writes the CA's certificate, and a bundle of systemRoots and
// it, into dir, readable by all. The CA's key is never written.
func WriteTrust(dir string, ca *CA, systemRoots []byte) (Trust, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil { //nolint:gosec // the server must read the CA's certificate; nothing secret is here
		return Trust{}, fmt.Errorf("make %s: %w", dir, err)
	}
	t := Trust{CAFile: filepath.Join(dir, "ca.pem"), BundleFile: filepath.Join(dir, "ca-bundle.pem")}
	bundle := append(append([]byte{}, systemRoots...), '\n')
	bundle = append(bundle, ca.CertPEM()...)
	for path, body := range map[string][]byte{t.CAFile: ca.CertPEM(), t.BundleFile: bundle} {
		if err := os.WriteFile(path, body, 0o644); err != nil { //nolint:gosec // a public certificate, which the unprivileged server must read
			return Trust{}, fmt.Errorf("write %s: %w", path, err)
		}
	}
	return t, nil
}

// Env is what the server's environment needs to go through the proxy at
// proxyAddr and trust its CA: Go (SSL_CERT_FILE is its system pool), Node,
// Python's requests and pip, curl and git.
func Env(proxyAddr string, t Trust) []string {
	url := "http://" + proxyAddr
	return []string{
		"HTTPS_PROXY=" + url,
		"HTTP_PROXY=" + url,
		"https_proxy=" + url,
		"http_proxy=" + url,
		"SSL_CERT_FILE=" + t.BundleFile,
		"NODE_EXTRA_CA_CERTS=" + t.CAFile,
		"REQUESTS_CA_BUNDLE=" + t.BundleFile,
		"PIP_CERT=" + t.BundleFile,
		"CURL_CA_BUNDLE=" + t.BundleFile,
		"GIT_SSL_CAINFO=" + t.BundleFile,
	}
}

// errNoRoots is returned when no system roots file could be read.
var errNoRoots = errors.New("no system roots file found")

// SystemRoots reads the first of the usual system roots files that exists.
func SystemRoots() ([]byte, error) {
	for _, f := range []string{
		"/etc/ssl/certs/ca-certificates.crt",
		"/etc/pki/tls/certs/ca-bundle.crt",
		"/etc/ssl/cert.pem",
	} {
		if b, err := os.ReadFile(f); err == nil {
			return b, nil
		}
	}
	return nil, errNoRoots
}
