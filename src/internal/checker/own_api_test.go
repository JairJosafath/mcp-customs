package checker

import (
	"context"
	"errors"
	"testing"
)

// apiHost is the stack's own API host in tests.
const apiHost = "abc123.execute-api.eu-west-1.amazonaws.com"

// fakeDNS answers from a table; a name not in it doesn't resolve.
func fakeDNS(table map[string][]string) LookupHost {
	return func(_ context.Context, host string) ([]string, error) {
		if got, ok := table[host]; ok {
			return got, nil
		}
		return nil, errors.New("no such host")
	}
}

// The addresses here are in API Gateway's published ranges for eu-west-1
// (internal/ownapi), or outside every range.
var testDNS = fakeDNS(map[string][]string{
	apiHost:                {"3.248.245.10"},
	"api.open-meteo.com":   {"198.51.100.7"},
	"customs.attacker.net": {"198.51.100.7", "3.248.245.10"},
	"mapped.attacker.net":  {"::ffff:108.128.160.7"},
	"other.attacker.net":   {"3.253.148.9"},
})

func TestOwnAPIRefusalRefusesTheAPIsNamesAndNamesThatResolveIntoItsRanges(t *testing.T) {
	for name, tc := range map[string]struct {
		api    string
		lookup LookupHost
		hosts  []string
		refuse bool
	}{
		"the API host":                       {apiHost, testDNS, []string{"api.open-meteo.com", apiHost}, true},
		"the API host in capitals, with dot": {apiHost, nil, []string{"ABC123.Execute-API.eu-west-1.amazonaws.com."}, true},
		"the FIPS form":                      {apiHost, nil, []string{"abc123.execute-api-fips.eu-west-1.amazonaws.com"}, true},
		"the dual-stack form":                {apiHost, nil, []string{"abc123.execute-api.eu-west-1.api.aws"}, true},
		"a name resolving into the ranges":   {apiHost, testDNS, []string{"customs.attacker.net"}, true},
		"a name resolving into them, mapped": {apiHost, testDNS, []string{"mapped.attacker.net"}, true},
		"a name resolving elsewhere in them": {apiHost, testDNS, []string{"other.attacker.net"}, true},
		"an API host that isn't API Gateway": {"api.example.com", testDNS, []string{"api.open-meteo.com"}, true},
		"a purpose's own host":               {apiHost, testDNS, []string{"api.open-meteo.com"}, false},
		"a name that doesn't resolve":        {apiHost, testDNS, []string{"nowhere.example"}, false},
		"no hosts":                           {apiHost, fakeDNS(nil), []string{}, false},
		"no API host to keep out":            {"", testDNS, []string{"customs.attacker.net"}, false},
	} {
		got := ownAPIRefusal(context.Background(), tc.api, tc.lookup, tc.hosts)
		if (got != "") != tc.refuse {
			t.Errorf("%s: refusal %q, want refused %v", name, got, tc.refuse)
		}
	}
}

func TestOwnAPIRefusalGivesTheSameAnswerWhileTheAPIsAddressesRotate(t *testing.T) {
	// The API's host answers a different address of its ranges each time,
	// or none, as API Gateway's DNS does; the hosts' own answers don't move.
	rotation := [][]string{{"3.248.245.10"}, {"3.253.148.9"}, nil}
	calls := 0
	lookup := func(ctx context.Context, host string) ([]string, error) {
		if host == apiHost {
			got := rotation[calls%len(rotation)]
			calls++
			if got == nil {
				return nil, errors.New("no such host")
			}
			return got, nil
		}
		return testDNS(ctx, host)
	}
	for _, host := range []string{"customs.attacker.net", "other.attacker.net", "api.open-meteo.com"} {
		first := ownAPIRefusal(context.Background(), apiHost, lookup, []string{host})
		for range 2 * len(rotation) {
			if got := ownAPIRefusal(context.Background(), apiHost, lookup, []string{host}); got != first {
				t.Errorf("%s: refusal %q, then %q", host, first, got)
			}
		}
	}
}
