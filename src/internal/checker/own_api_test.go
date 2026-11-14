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

var testDNS = fakeDNS(map[string][]string{
	apiHost:                {"203.0.113.10", "2001:db8::10"},
	"api.open-meteo.com":   {"198.51.100.7"},
	"customs.attacker.net": {"198.51.100.7", "203.0.113.10"},
	"mapped.attacker.net":  {"::ffff:203.0.113.10"},
	"v6.attacker.net":      {"2001:db8::10"},
})

func TestOwnAPIRefusalRefusesTheAPIHostAndNamesThatResolveToIt(t *testing.T) {
	for name, tc := range map[string]struct {
		api    string
		lookup LookupHost
		hosts  []string
		refuse bool
	}{
		"the API host":                       {apiHost, testDNS, []string{"api.open-meteo.com", apiHost}, true},
		"the API host in capitals, with dot": {apiHost, nil, []string{"ABC123.Execute-API.eu-west-1.amazonaws.com."}, true},
		"a name resolving to its IPv4":       {apiHost, testDNS, []string{"customs.attacker.net"}, true},
		"a name resolving to it, mapped":     {apiHost, testDNS, []string{"mapped.attacker.net"}, true},
		"a name resolving to its IPv6":       {apiHost, testDNS, []string{"v6.attacker.net"}, true},
		"an API host that doesn't resolve":   {apiHost, fakeDNS(nil), []string{"api.open-meteo.com"}, true},
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
