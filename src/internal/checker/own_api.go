package checker

import (
	"context"
	"fmt"
	"net/netip"
	"strings"

	"github.com/aws/aws-durable-execution-sdk-go/durable"

	"github.com/JairJosafath/mcp-customs/src/internal/findings"
)

// LookupHost resolves a host name to its addresses, as
// net.Resolver.LookupHost does.
type LookupHost func(ctx context.Context, host string) ([]string, error)

// ownAPIRefusal says why hosts may not be allowed: one of them is the
// stack's own API host, or resolves to one of its addresses. It is empty
// when none does, or when there is no API host to keep out. A name that
// doesn't resolve reaches nothing, so it is not refused; if the API host
// itself doesn't resolve, nothing can be compared, so every host is.
func ownAPIRefusal(ctx context.Context, apiHost string, lookup LookupHost, hosts []string) string {
	api := normalHost(apiHost)
	if api == "" || len(hosts) == 0 {
		return ""
	}
	for _, h := range hosts {
		if normalHost(h) == api {
			return fmt.Sprintf("the judge asked to allow %q, the stack's own API host", h)
		}
	}
	if lookup == nil {
		return ""
	}
	apiAddrs := addresses(ctx, lookup, api)
	if len(apiAddrs) == 0 {
		return "the stack's own API host did not resolve, so no host could be told apart from it"
	}
	for _, h := range hosts {
		for a := range addresses(ctx, lookup, normalHost(h)) {
			if apiAddrs[a] {
				return fmt.Sprintf("the judge asked to allow %q, which resolves to %s, an address of the stack's own API", h, a)
			}
		}
	}
	return ""
}

// ownAPIRefusal checks hosts against the stack's own API host, resolving
// both, in a step of its own: a replay reads what it found.
func (r *run) ownAPIRefusal(ctx durable.Context, hosts []string) (string, error) {
	return durable.Step(ctx, "own-api", func(sc durable.StepContext) (string, error) {
		return ownAPIRefusal(sc, r.deps.APIHost, r.deps.LookupHost, hosts), nil
	})
}

// refuseOwnAPI is the outcome of an allow refused for reaching the stack's
// own API.
func (r *run) refuseOwnAPI(refusal string) outcome {
	r.ownAPI = true
	return outcome{
		Summary:  "Refused to allow a host that is, or resolves to, MCP Customs' own API; the judge investigates nothing more and a person must review.",
		Findings: []findings.Finding{{Source: findings.Code, Rule: findings.RuleOwnAPIHost, Evidence: refusal}},
	}
}

// normalHost is a host name as DNS compares it: lowercase, without a
// trailing dot.
func normalHost(h string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(h)), ".")
}

// addresses are the addresses host resolves to, an IPv4 address mapped
// into IPv6 read as IPv4; none when it doesn't resolve.
func addresses(ctx context.Context, lookup LookupHost, host string) map[netip.Addr]bool {
	got, err := lookup(ctx, host)
	if err != nil {
		return nil
	}
	out := map[netip.Addr]bool{}
	for _, s := range got {
		if a, err := netip.ParseAddr(s); err == nil {
			out[a.Unmap().WithZone("")] = true
		}
	}
	return out
}
