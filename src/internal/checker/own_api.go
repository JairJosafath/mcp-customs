package checker

import (
	"context"
	"fmt"
	"net/netip"

	"github.com/aws/aws-durable-execution-sdk-go/durable"

	"github.com/JairJosafath/mcp-customs/src/internal/findings"
	"github.com/JairJosafath/mcp-customs/src/internal/ownapi"
)

// LookupHost resolves a host name to its addresses, as
// net.Resolver.LookupHost does.
type LookupHost func(ctx context.Context, host string) ([]string, error)

// ownAPIRefusal says why hosts may not be allowed: one of them is not a
// plain ASCII host name (ownapi.ValidHost), which a transport could map onto
// the API's own name, or it names the
// stack's own API, in any of its forms, or resolves into API Gateway's
// published ranges for its region. The ranges are fixed, so a host gets the
// same answer from run to run however the API's own addresses rotate. It is
// empty when no host is refused, or when there is no API host to keep out.
// A name that doesn't resolve reaches nothing, so it is not refused; an
// API host that isn't API Gateway's refuses every host, since nothing could
// be told apart from it.
func ownAPIRefusal(ctx context.Context, apiHost string, lookup LookupHost, hosts []string) string {
	for _, h := range hosts {
		if err := ownapi.ValidHost(h); err != nil {
			return fmt.Sprintf("the judge asked to allow %q, which no layer could tell apart from the stack's own API: %v", h, err)
		}
	}
	if ownapi.NormalHost(apiHost) == "" || len(hosts) == 0 {
		return ""
	}
	api, err := ownapi.Parse(apiHost)
	if err != nil {
		return "no host could be told apart from the stack's own API: " + err.Error()
	}
	for _, h := range hosts {
		if api.IsHost(h) {
			return fmt.Sprintf("the judge asked to allow %q, a name of the stack's own API", h)
		}
	}
	if lookup == nil {
		return ""
	}
	for _, h := range hosts {
		for _, a := range addresses(ctx, lookup, ownapi.NormalHost(h)) {
			if api.Serves(a) {
				return fmt.Sprintf("the judge asked to allow %q, which resolves to %s, in API Gateway's published ranges for %s, where the stack's own API is served", h, a, api.Region)
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

// addresses are the addresses host resolves to, in order, an IPv4 address mapped
// into IPv6 read as IPv4; none when it doesn't resolve.
func addresses(ctx context.Context, lookup LookupHost, host string) []netip.Addr {
	got, err := lookup(ctx, host)
	if err != nil {
		return nil
	}
	out := make([]netip.Addr, 0, len(got))
	for _, s := range got {
		if a, err := netip.ParseAddr(s); err == nil {
			out = append(out, a.Unmap().WithZone(""))
		}
	}
	return out
}
