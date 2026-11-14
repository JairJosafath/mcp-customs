// Package netaddr tells a public internet address from one inside a
// network: loopback, link-local, private, the instance metadata and the
// other ranges a request from the sandbox must never reach. The web
// function reads submitted addresses with it, and the egress proxy the
// addresses it is about to dial.
package netaddr

import (
	"net/netip"
	"slices"
)

// notPublic are the address ranges a remote server can't be at: what a
// request from the sandbox would turn into a request inside a network
// rather than to the internet.
var notPublic = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),      // this network
	netip.MustParsePrefix("10.0.0.0/8"),     // private
	netip.MustParsePrefix("100.64.0.0/10"),  // shared (carrier-grade NAT)
	netip.MustParsePrefix("127.0.0.0/8"),    // loopback
	netip.MustParsePrefix("169.254.0.0/16"), // link-local, and the instance metadata at .169.254
	netip.MustParsePrefix("172.16.0.0/12"),  // private
	netip.MustParsePrefix("192.0.0.0/24"),   // IETF protocol assignments
	netip.MustParsePrefix("192.168.0.0/16"), // private
	netip.MustParsePrefix("198.18.0.0/15"),  // benchmarking
	netip.MustParsePrefix("224.0.0.0/3"),    // multicast and reserved, and broadcast
	netip.MustParsePrefix("::/128"),         // unspecified
	netip.MustParsePrefix("::1/128"),        // loopback
	netip.MustParsePrefix("::/96"),          // IPv4-compatible, such as ::127.0.0.1
	netip.MustParsePrefix("64:ff9b::/96"),   // IPv4 translated, which can reach the ranges above
	netip.MustParsePrefix("64:ff9b:1::/48"), // IPv4 translated for local use
	netip.MustParsePrefix("2001::/32"),      // Teredo, which carries an IPv4 address
	netip.MustParsePrefix("2002::/16"),      // 6to4, which carries an IPv4 address
	netip.MustParsePrefix("fc00::/7"),       // unique local, and the instance metadata at fd00:ec2::254
	netip.MustParsePrefix("fe80::/10"),      // link-local
	netip.MustParsePrefix("fec0::/10"),      // site-local, deprecated but still routed inside some networks
	netip.MustParsePrefix("ff00::/8"),       // multicast
}

// Public says whether addr is outside every range a request inside a
// network would reach. An IPv4-mapped address reads as its IPv4 address.
func Public(addr netip.Addr) bool {
	addr = addr.Unmap()
	return addr.IsValid() && !slices.ContainsFunc(notPublic, func(p netip.Prefix) bool { return p.Contains(addr) })
}
