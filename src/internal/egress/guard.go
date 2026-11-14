package egress

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
)

// ErrRefusedAddress is the error of a connection Guard refuses.
var ErrRefusedAddress = errors.New("the address is refused")

// A Guard dials the upstream connections of allowed requests: it resolves
// the host once, refuses the connection if any address it resolves to is
// refused, and dials the address it checked, never the name again, so a
// DNS answer that changes in between (rebinding) can't reach a refused
// address. Use its DialContext as the Upstream transport's.
type Guard struct {
	// Resolver resolves the hosts dialed.
	Resolver Resolver
	// Refused says whether an address may never be reached.
	Refused func(netip.Addr) bool
	// RefusedNames are names whose addresses, resolved at each dial, are
	// refused too.
	RefusedNames []string
	// Exempt are names whose addresses are not checked: the install's Go
	// proxy on the stack's own API, which the proxy holds to GETs under its
	// prefix while an install runs.
	Exempt []string
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
	if !slices.Contains(g.Exempt, normalHost(host)) {
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

// refused answers the first of addrs that is refused. A refused name that
// doesn't resolve refuses nothing.
func (g Guard) refused(ctx context.Context, addrs []netip.Addr) (netip.Addr, bool) {
	deny := map[netip.Addr]bool{}
	for _, name := range g.RefusedNames {
		got, _ := g.Resolver.LookupNetIP(ctx, "ip", name)
		for _, a := range got {
			deny[a.Unmap().WithZone("")] = true
		}
	}
	for _, a := range addrs {
		a = a.Unmap().WithZone("")
		if deny[a] || (g.Refused != nil && g.Refused(a)) {
			return a, true
		}
	}
	return netip.Addr{}, false
}
