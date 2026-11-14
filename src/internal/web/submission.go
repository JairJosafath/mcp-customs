package web

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"unicode"

	"github.com/JairJosafath/mcp-customs/src/internal/harness"
	"github.com/JairJosafath/mcp-customs/src/internal/netaddr"
	"github.com/JairJosafath/mcp-customs/src/internal/store"
)

// maxRefLength bounds a submission's reference, as the Checker does.
const maxRefLength = 512

// The messages of a submission that names no server the Checker can check.
var (
	errBadKind   = errors.New(`the kind must be "go", "npm", "pypi" or "remote"`)
	errBadRef    = fmt.Errorf("the ref must be 1 to %d characters", maxRefLength)
	errBadURL    = errors.New("a remote server's ref must be an https:// URL with a host, and no user, password or fragment")
	errNotPublic = errors.New("a remote server's host must be a public name or address, written plainly: " +
		"not localhost, a single label, a numeric name, a loopback, private, link-local, shared or metadata address, " +
		"a zone or percent-encoding")
)

// pinned say, for each package kind, what it is called and what a pinned
// ref of it looks like.
var pinned = map[string]struct{ what, example string }{
	"go":   {"a Go module", "github.com/acme/weather-mcp@v1.2.3"},
	"npm":  {"an npm package", "weather-mcp@1.0.0"},
	"pypi": {"a PyPI package", "weather-mcp@1.0.0"},
}

// parseSubmission reads a submitted kind and ref into what the Checker
// takes: a package pinned to one version (go, npm or pypi, as the harness
// installs it), or a remote server's https URL. Anything else is refused
// with a message a person can act on.
func parseSubmission(kind, ref string) (store.Submission, error) {
	kind, ref = strings.TrimSpace(kind), strings.TrimSpace(ref)
	if ref == "" || len(ref) > maxRefLength {
		return store.Submission{}, errBadRef
	}
	switch kind {
	case "go", "npm", "pypi":
		if _, err := harness.ParsePackage(kind, ref); err != nil {
			p := pinned[kind]
			return store.Submission{}, fmt.Errorf("the ref of %s must be its name pinned to one version, such as %s", p.what, p.example)
		}
	case "remote":
		if err := checkRemoteURL(ref); err != nil {
			return store.Submission{}, err
		}
	default:
		return store.Submission{}, errBadKind
	}
	return store.Submission{Kind: kind, Ref: ref}, nil
}

// checkRemoteURL accepts an https URL of printable ASCII with a host and
// no credentials or fragment.
func checkRemoteURL(ref string) error {
	for _, r := range ref {
		if r > unicode.MaxASCII || !unicode.IsPrint(r) || r == ' ' {
			return errBadURL
		}
	}
	u, err := url.Parse(ref)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Fragment != "" || u.Opaque != "" {
		return errBadURL
	}
	// A zone ([fe80::1%25eth0]) or a percent-encoded host
	// (127.0.0.%EF%BC%91, a full-width 1 some resolvers read as 1) can't
	// be checked as written: neither belongs in a public server's URL.
	if strings.Contains(rawAuthority(ref), "%") || !publicHost(u.Hostname()) {
		return errNotPublic
	}
	return nil
}

// rawAuthority is the authority of ref, an absolute URL, as written: what
// follows the scheme's "//" up to the path, query or fragment.
func rawAuthority(ref string) string {
	_, rest, _ := strings.Cut(ref, "//")
	if end := strings.IndexAny(rest, "/?#"); end >= 0 {
		return rest[:end]
	}
	return rest
}

// metadataHosts are names that answer with a cloud's instance metadata.
var metadataHosts = []string{
	"metadata", "metadata.google.internal", "metadata.goog", "instance-data", "instance-data.ec2.internal",
}

// publicHost reports whether host, a URL's host without brackets or port,
// names a public server: an address outside notPublic, or a name of at
// least two labels whose last isn't numeric (which some resolvers read as
// an address, such as 2130706433 or 0x7f.1), and that isn't localhost or
// a metadata name. A public name that resolves to a private address is
// the sandbox's egress to refuse: only the place that connects can know.
func publicHost(host string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if addr, err := netip.ParseAddr(host); err == nil {
		return netaddr.Public(addr)
	}
	labels := strings.Split(host, ".")
	last := labels[len(labels)-1]
	switch {
	case len(labels) < 2, last == "localhost", last == "internal", last == "local":
		return false
	case slices.Contains(metadataHosts, host):
		return false
	case strings.HasPrefix(last, "0x") || strings.Trim(last, "0123456789") == "":
		return false
	}
	return true
}

// checkIDLength is the length of a check ID: 16 bytes, base64url.
const checkIDLength = 22

// NewCheckID makes a fresh, unguessable check ID of 128 random bits.
func NewCheckID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("make a check id: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// maxIdempotencyKey bounds a client's idempotency key.
const maxIdempotencyKey = 128

// errBadIdempotencyKey says an Idempotency-Key header can't be used.
var errBadIdempotencyKey = fmt.Errorf("an Idempotency-Key must be 1 to %d printable ASCII characters", maxIdempotencyKey)

// checkIDFor is the check ID of a client's idempotency key: the same key
// gives the same ID, so a retried request starts no second check, and the
// key sent again with another submission is refused by the Checker's
// durable execution name.
func checkIDFor(key string) (string, error) {
	if key == "" || len(key) > maxIdempotencyKey {
		return "", errBadIdempotencyKey
	}
	for _, r := range key {
		if r > unicode.MaxASCII || !unicode.IsPrint(r) {
			return "", errBadIdempotencyKey
		}
	}
	sum := sha256.Sum256([]byte(key))
	return base64.RawURLEncoding.EncodeToString(sum[:])[:checkIDLength], nil
}
