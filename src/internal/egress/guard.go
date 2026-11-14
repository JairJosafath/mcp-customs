package egress

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"

	"github.com/JairJosafath/mcp-customs/src/internal/netaddr"
	"github.com/JairJosafath/mcp-customs/src/internal/ownapi"
)

// ErrRefusedAddress is the error of a connection Guard refuses.
var ErrRefusedAddress = errors.New("the address is refused")

// A Guard dials the upstream connections of allowed requests: it resolves
// the host once, refuses the connection if any address it resolves to is
// refused or isn't public (loopback, link-local, private, the instance
// metadata: netaddr.Public), so a wildcard-DNS name such as
// 169.254.169.254.nip.io can't reach inside a network, and dials the address it checked, never the name again, so a
// DNS answer that changes in between (rebinding) can't reach a refused
// address. Use its DialContext as the Upstream transport's. The one
// connection it doesn't check is one dialed for an install's GET under an
// InstallGet prefix, such as the stack's demo Go proxy on the API itself:
// the proxy marks those requests and keeps none of their
// connections, so nothing else is sent on them.
type Guard struct {
	// Resolver resolves the hosts dialed.
	Resolver Resolver
	// Refused says whether an address may never be reached.
	Refused func(netip.Addr) bool
	// RefusedNames are names whose addresses, resolved at each dial, are
	// refused too.
	RefusedNames []string
	// Dial connects to an address, as net.Dialer.DialContext does.
	Dial func(ctx context.Context, network, address string) (net.Conn, error)
}

// DialContext connects to address, host:port, unless the host resolves to
// a refused address.
func (g Guard) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, fmt.Errorf("dialing %s: %w", address, err)
	}
	addrs, err := g.lookup(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("resolving %s: %w", host, err)
	}
	if !isInstallGet(ctx) {
		if a, refused := g.refused(ctx, addrs); refused {
			return nil, fmt.Errorf("%s resolves to %s: %w", host, a, ErrRefusedAddress)
		}
	}
	var errs []error
	for _, a := range addrs {
		conn, err := g.Dial(ctx, network, net.JoinHostPort(a.String(), port))
		if err == nil {
			return conn, nil
		}
		errs = append(errs, err)
	}
	return nil, fmt.Errorf("dialing %s: %w", host, errors.Join(errs...))
}

// lookup resolves host, or reads it when it is an address.
func (g Guard) lookup(ctx context.Context, host string) ([]netip.Addr, error) {
	if a, err := netip.ParseAddr(host); err == nil {
		return []netip.Addr{a}, nil
	}
	addrs, err := g.Resolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, err
	}
	if len(addrs) == 0 {
		return nil, errors.New("no addresses")
	}
	return addrs, nil
}

// refused answers the first of addrs that is refused or isn't public. A refused name that
// doesn't resolve refuses nothing.
func (g Guard) refused(ctx context.Context, addrs []netip.Addr) (netip.Addr, bool) {
	deny := map[netip.Addr]bool{}
	for _, name := range g.RefusedNames {
		got, _ := g.Resolver.LookupNetIP(ctx, "ip", name)
		for _, a := range got {
			deny[ownapi.Canonical(a)] = true
		}
	}
	for _, a := range addrs {
		a = ownapi.Canonical(a)
		if deny[a] || !netaddr.Public(a) || (g.Refused != nil && g.Refused(a)) {
			return a, true
		}
	}
	return netip.Addr{}, false
}

// installGetKey marks a request's context as an install's GET under an
// InstallGet prefix.
type installGetKey struct{}

// withInstallGet marks ctx as an install's GET under an InstallGet prefix.
func withInstallGet(ctx context.Context) context.Context {
	return context.WithValue(ctx, installGetKey{}, true)
}

// isInstallGet says whether ctx was marked by withInstallGet.
func isInstallGet(ctx context.Context) bool {
	on, _ := ctx.Value(installGetKey{}).(bool)
	return on
}
