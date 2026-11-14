package egress

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"slices"
	"testing"
)

// tableResolver answers each name from a list of answers, the next one at
// each lookup, the last one again once they run out, as a rebinding DNS
// server would.
type tableResolver struct {
	answers map[string][][]string
	calls   map[string]int
}

func (r *tableResolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	list, ok := r.answers[host]
	if !ok {
		return nil, errors.New("no such host")
	}
	n := min(r.calls[host], len(list)-1)
	r.calls[host]++
	out := make([]netip.Addr, 0, len(list[n]))
	for _, s := range list[n] {
		out = append(out, netip.MustParseAddr(s))
	}
	return out, nil
}

func (*tableResolver) LookupTXT(context.Context, string) ([]string, error) { return nil, nil }

// apiRange stands in for API Gateway's published ranges.
var apiRange = netip.MustParsePrefix("3.248.245.0/24")

func testGuard(answers map[string][][]string, dialed *[]string) Guard {
	return Guard{
		Resolver:     &tableResolver{answers: answers, calls: map[string]int{}},
		Refused:      apiRange.Contains,
		RefusedNames: []string{"abc123.execute-api.eu-west-1.amazonaws.com"},
		Dial: func(_ context.Context, _, address string) (net.Conn, error) {
			*dialed = append(*dialed, address)
			c, s := net.Pipe()
			_ = s.Close()
			return c, nil
		},
	}
}

func TestGuardRefusesEveryConnectionToTheAPIsAddresses(t *testing.T) {
	answers := map[string][][]string{
		"abc123.execute-api.eu-west-1.amazonaws.com": {{"3.248.245.10", "2a05:d018::10"}},
		"api.weather.example":                        {{"198.51.100.7"}},
		"in-range.attacker.net":                      {{"198.51.100.8", "3.248.245.99"}},
		"api-v6.attacker.net":                        {{"2a05:d018::10"}},
		"mapped.attacker.net":                        {{"::ffff:3.248.245.10"}},
		"nat64.attacker.net":                         {{"64:ff9b::3.248.245.10"}},
		"compat.attacker.net":                        {{"::3.248.245.10"}},
		"rebinding.attacker.net":                     {{"198.51.100.9"}, {"3.248.245.10"}},
	}
	for host, want := range map[string]string{
		"api.weather.example:443":                        "198.51.100.7:443",
		"in-range.attacker.net:443":                      "",
		"api-v6.attacker.net:443":                        "",
		"mapped.attacker.net:443":                        "",
		"nat64.attacker.net:443":                         "",
		"compat.attacker.net:443":                        "",
		"3.248.245.10:443":                               "",
		"abc123.execute-api.eu-west-1.amazonaws.com:443": "",
	} {
		var dialed []string
		conn, err := testGuard(answers, &dialed).DialContext(t.Context(), "tcp", host)
		if want == "" {
			if !errors.Is(err, ErrRefusedAddress) || len(dialed) != 0 {
				t.Errorf("%s: err %v, dialed %v; want refused, nothing dialed", host, err, dialed)
			}
			continue
		}
		if err != nil || len(dialed) == 0 || dialed[0] != want {
			t.Errorf("%s: err %v, dialed %v; want %s", host, err, dialed, want)
			continue
		}
		_ = conn.Close()
	}
	// A rebinding name is dialed at the address that was checked, never
	// resolved again into the API's.
	var dialed []string
	conn, err := testGuard(answers, &dialed).DialContext(t.Context(), "tcp", "rebinding.attacker.net:443")
	if err != nil || !slices.Equal(dialed, []string{"198.51.100.9:443"}) {
		t.Fatalf("rebinding: err %v, dialed %v; want the checked address alone", err, dialed)
	}
	_ = conn.Close()
}

func TestGuardRefusesANameThatDoesNotResolve(t *testing.T) {
	var dialed []string
	if _, err := testGuard(nil, &dialed).DialContext(t.Context(), "tcp", "nowhere.example:443"); err == nil || len(dialed) != 0 {
		t.Errorf("err %v, dialed %v; want an error, nothing dialed", err, dialed)
	}
}

func TestGuardReachesTheAPIOnlyForARequestMarkedAsAnInstallsGet(t *testing.T) {
	answers := map[string][][]string{"abc123.execute-api.eu-west-1.amazonaws.com": {{"3.248.245.10"}}}
	const api = "abc123.execute-api.eu-west-1.amazonaws.com:443"
	var dialed []string
	if _, err := testGuard(answers, &dialed).DialContext(t.Context(), "tcp", api); !errors.Is(err, ErrRefusedAddress) || len(dialed) != 0 {
		t.Errorf("unmarked, by the API's own name: err %v, dialed %v; want refused", err, dialed)
	}
	conn, err := testGuard(answers, &dialed).DialContext(withInstallGet(t.Context()), "tcp", api)
	if err != nil || !slices.Equal(dialed, []string{"3.248.245.10:443"}) {
		t.Fatalf("marked as an install's GET: err %v, dialed %v; want the API's address", err, dialed)
	}
	_ = conn.Close()
}

func TestGuardRefusesANameThatResolvesInsideANetwork(t *testing.T) {
	answers := map[string][][]string{
		"169.254.169.254.nip.io":   {{"169.254.169.254"}},
		"127.0.0.1.nip.io":         {{"127.0.0.1"}},
		"169-254-169-254.sslip.io": {{"169.254.169.254"}},
		"localtest.me":             {{"127.0.0.1", "::1"}},
		"private.attacker.net":     {{"198.51.100.8", "10.0.0.5"}},
		"metadata-v6.attacker.net": {{"fd00:ec2::254"}},
		"mapped-lo.attacker.net":   {{"::ffff:127.0.0.1"}},
	}
	for host := range answers {
		var dialed []string
		_, err := testGuard(answers, &dialed).DialContext(t.Context(), "tcp", net.JoinHostPort(host, "443"))
		if !errors.Is(err, ErrRefusedAddress) || len(dialed) != 0 {
			t.Errorf("%s: err %v, dialed %v; want refused, nothing dialed", host, err, dialed)
		}
	}
	var dialed []string
	if _, err := testGuard(nil, &dialed).DialContext(t.Context(), "tcp", "169.254.169.254:80"); !errors.Is(err, ErrRefusedAddress) || len(dialed) != 0 {
		t.Errorf("the metadata address itself: err %v, dialed %v; want refused", err, dialed)
	}
}

func TestGuardRefusesAnInstallsGetToANameThatResolvesInsideANetwork(t *testing.T) {
	answers := map[string][][]string{"metadata.attacker.net": {{"169.254.169.254"}}}
	var dialed []string
	_, err := testGuard(answers, &dialed).DialContext(withInstallGet(t.Context()), "tcp", "metadata.attacker.net:443")
	if !errors.Is(err, ErrRefusedAddress) || len(dialed) != 0 {
		t.Errorf("err %v, dialed %v; want refused, nothing dialed", err, dialed)
	}
}
