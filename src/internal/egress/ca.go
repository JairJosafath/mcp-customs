package egress

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"sync"
	"time"
)

// A CA is the proxy's own certificate authority. Its key lives only in the
// harness's memory: it is never written anywhere, so the server under test,
// which runs as another user, can't read it. Only its certificate is
// handed out, for the server to trust.
type CA struct {
	cert *x509.Certificate
	key  crypto.Signer
	pem  []byte
	now  func() time.Time

	mu     sync.Mutex
	leaves map[string]*tls.Certificate
}

// Validity windows. Leaves outlast a clock moved a few months forward.
const (
	caLifetime   = 10 * 365 * 24 * time.Hour
	leafLifetime = 2 * 365 * 24 * time.Hour
	backdate     = 24 * time.Hour
)

// NewCA makes a fresh certificate authority, with a name a developer's
// machine might have, valid from a day before now.
func NewCA(now func() time.Time) (*CA, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("make the CA's key: %w", err)
	}
	start := now().Add(-backdate)
	tmpl := &x509.Certificate{
		SerialNumber:          serial(),
		Subject:               pkix.Name{CommonName: "Local Development CA", Organization: []string{"Development"}},
		NotBefore:             start,
		NotAfter:              start.Add(caLifetime),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		return nil, fmt.Errorf("sign the CA's certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("read the CA's certificate: %w", err)
	}
	return &CA{
		cert:   cert,
		key:    key,
		pem:    pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		now:    now,
		leaves: map[string]*tls.Certificate{},
	}, nil
}

// CertPEM is the CA's certificate, PEM-encoded: what the server trusts.
func (ca *CA) CertPEM() []byte {
	return ca.pem
}

// Pool is a pool holding only the CA, for tests and clients of the proxy.
func (ca *CA) Pool() *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(ca.cert)
	return p
}

// leaf is a certificate for host signed by the CA, made once per host.
func (ca *CA) leaf(host string) (*tls.Certificate, error) {
	host = normalHost(host)
	if host == "" {
		return nil, errors.New("no host to make a certificate for")
	}
	ca.mu.Lock()
	defer ca.mu.Unlock()
	if c, ok := ca.leaves[host]; ok {
		return c, nil
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("make a key for %s: %w", host, err)
	}
	start := ca.now().Add(-backdate)
	tmpl := &x509.Certificate{
		SerialNumber: serial(),
		Subject:      pkix.Name{CommonName: host},
		NotBefore:    start,
		NotAfter:     start.Add(leafLifetime),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if ip := net.ParseIP(host); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.DNSNames = []string{host}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, key.Public(), ca.key)
	if err != nil {
		return nil, fmt.Errorf("sign a certificate for %s: %w", host, err)
	}
	c := &tls.Certificate{Certificate: [][]byte{der, ca.cert.Raw}, PrivateKey: key}
	ca.leaves[host] = c
	return c, nil
}

func serial() *big.Int {
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		// crypto/rand never fails on Linux; a fixed serial still works.
		return big.NewInt(1)
	}
	return n
}
