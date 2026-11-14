package ownapi

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
)

// Bounds on a host name (RFC 1035).
const (
	maxHost  = 253
	maxLabel = 63
)

// ValidHost refuses anything but a plain ASCII host name: labels of
// letters, digits and inner hyphens, 1 to 63 characters, 253 in all, with
// at most one trailing dot. Every layer that keeps the API out reads names
// with it, so none reads a name differently from the transport that dials
// it: a soft hyphen, an ideographic full stop or a fullwidth letter, which
// IDNA maps onto the API's own name, is refused, and so is a punycode
// ("xn--") label, which could spell them. So is an IP address in any form
// resolvers read (1.2.3.4, 127.1, 2130706433, 0x7f.1): its last label is
// a number, which no top-level domain is.
func ValidHost(host string) error {
	name := strings.TrimSuffix(host, ".")
	if name == "" || len(name) > maxHost {
		return fmt.Errorf("%q is not a host name: it must be 1 to %d characters", host, maxHost)
	}
	labels := strings.Split(name, ".")
	for _, l := range labels {
		if err := validLabel(l); err != nil {
			return fmt.Errorf("%q is not a host name: %w", host, err)
		}
	}
	if isNumber(strings.ToLower(labels[len(labels)-1])) {
		return fmt.Errorf("%q is an IP address; only host names are allowed", host)
	}
	return nil
}

// validLabel refuses a label that isn't letters, digits and inner hyphens,
// or is punycode.
func validLabel(l string) error {
	if l == "" || len(l) > maxLabel {
		return fmt.Errorf("each label must be 1 to %d characters", maxLabel)
	}
	if l[0] == '-' || l[len(l)-1] == '-' {
		return errors.New("a label can't start or end with a hyphen")
	}
	for i := range len(l) {
		if !isLDH(l[i]) {
			return errors.New("only ASCII letters, digits, hyphens and dots are allowed")
		}
	}
	if strings.HasPrefix(strings.ToLower(l), "xn--") {
		return errors.New("a punycode (xn--) label is not allowed")
	}
	return nil
}

// isLDH says whether c is an ASCII letter, digit or hyphen.
func isLDH(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-'
}

// isNumber says whether l is a decimal or 0x hex number.
func isNumber(l string) bool {
	digits := "0123456789"
	if hex, ok := strings.CutPrefix(l, "0x"); ok {
		l, digits = hex, "0123456789abcdef"
	}
	return l != "" && strings.Trim(l, digits) == ""
}

// nat64 is the well-known NAT64 prefix (RFC 6052), which embeds an IPv4
// address in its last 32 bits.
var nat64 = netip.MustParsePrefix("64:ff9b::/96")

// Canonical is addr as an IPv4 address when it embeds one: IPv4-mapped
// (::ffff:a.b.c.d), IPv4-compatible (::a.b.c.d) or NAT64
// (64:ff9b::a.b.c.d), so an embedded address of the API's is compared as
// itself. Its zone is dropped.
func Canonical(addr netip.Addr) netip.Addr {
	addr = addr.Unmap().WithZone("")
	if !addr.Is6() {
		return addr
	}
	b := addr.As16()
	compatible := b == [16]byte{12: b[12], 13: b[13], 14: b[14], 15: b[15]} && (b[12]|b[13]|b[14]) != 0
	if compatible || nat64.Contains(addr) {
		return netip.AddrFrom4([4]byte(b[12:]))
	}
	return addr
}
