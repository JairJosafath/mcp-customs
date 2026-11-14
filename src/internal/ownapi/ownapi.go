// Package ownapi tells the stack's own API apart from every other host:
// the names it answers on and the addresses API Gateway serves it from.
// The Checker, the harness and the egress proxy all keep it out of the
// sandbox with it, against a fixed source: API Gateway's published
// address ranges, embedded, so the same host gets the same answer from
// run to run however the API's own addresses rotate.
package ownapi

import (
	"bufio"
	_ "embed"
	"fmt"
	"net/netip"
	"strings"
)

//go:embed api_gateway_ranges.txt
var rangesFile string

// An API is the stack's own API: its ID and region, from its
// execute-api host.
type API struct {
	// Host is the API's host as Parse read it, normalized.
	Host   string
	ID     string
	Region string
	ranges []netip.Prefix
}

// Parse reads the API from its host, <id>.execute-api.<region>.<suffix>.
// It refuses any other host, and a region with no published ranges: with
// nothing to compare against, nothing could be told apart from the API.
func Parse(host string) (API, error) {
	labels := strings.Split(NormalHost(host), ".")
	if len(labels) < 4 || labels[0] == "" || labels[1] != "execute-api" || labels[2] == "" {
		return API{}, fmt.Errorf("%q is not an API Gateway host, <id>.execute-api.<region>.<suffix>", host)
	}
	api := API{Host: strings.Join(labels, "."), ID: labels[0], Region: labels[2], ranges: regionRanges(labels[2])}
	if len(api.ranges) == 0 {
		return API{}, fmt.Errorf("API Gateway publishes no address ranges for %q, the region of %q", api.Region, host)
	}
	return api, nil
}

// IsHost says whether host names the API in any of its forms: the
// standard one, FIPS (execute-api-fips), dual-stack (…api.aws), a VPC
// endpoint's (<id>-<vpce>), or any other suffix. Its first label is the
// API's ID, alone or before a "-", and a later one starts "execute-api".
func (a API) IsHost(host string) bool {
	labels := strings.Split(NormalHost(host), ".")
	if a.ID == "" || len(labels) < 2 || (labels[0] != a.ID && !strings.HasPrefix(labels[0], a.ID+"-")) {
		return false
	}
	for _, l := range labels[1:] {
		if strings.HasPrefix(l, "execute-api") {
			return true
		}
	}
	return false
}

// Serves says whether addr is in API Gateway's published ranges for the
// API's region: an address the API, or any name for it, may resolve to.
// An IPv4 address embedded in IPv6 reads as IPv4 (Canonical).
func (a API) Serves(addr netip.Addr) bool {
	addr = Canonical(addr)
	for _, p := range a.ranges {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// NormalHost is a host name as DNS compares it: lowercase, without a
// trailing dot.
func NormalHost(host string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
}

// Names are the API's names whose addresses the egress proxy resolves and
// refuses: the standard one and the dual-stack one.
func (a API) Names() []string {
	return []string{a.Host, a.ID + ".execute-api." + a.Region + ".api.aws"}
}

// regionRanges are the published ranges for region.
func regionRanges(region string) []netip.Prefix {
	var out []netip.Prefix
	sc := bufio.NewScanner(strings.NewReader(rangesFile))
	for sc.Scan() {
		r, prefix, ok := strings.Cut(sc.Text(), " ")
		if !ok || r != region {
			continue
		}
		if p, err := netip.ParsePrefix(prefix); err == nil {
			out = append(out, p)
		}
	}
	return out
}
