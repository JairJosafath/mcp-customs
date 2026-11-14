package ownapi

import (
	"net/netip"
	"testing"
)

const apiHost = "abc123.execute-api.eu-west-1.amazonaws.com"

func mustParse(t *testing.T) API {
	t.Helper()
	api, err := Parse(apiHost)
	if err != nil {
		t.Fatal(err)
	}
	return api
}

func TestParseReadsTheIDAndRegionAndRefusesAnythingElse(t *testing.T) {
	api := mustParse(t)
	if api.ID != "abc123" || api.Region != "eu-west-1" {
		t.Errorf("Parse = %q in %q, want abc123 in eu-west-1", api.ID, api.Region)
	}
	for _, host := range []string{
		"", "api.example.com", "abc123.execute-api.amazonaws.com",
		"abc123.execute-api.nowhere-1.amazonaws.com", ".execute-api.eu-west-1.amazonaws.com",
	} {
		if _, err := Parse(host); err == nil {
			t.Errorf("Parse(%q) succeeded, want refused", host)
		}
	}
}

func TestIsHostNamesEveryFormOfTheAPIsHost(t *testing.T) {
	api := mustParse(t)
	for host, want := range map[string]bool{
		apiHost: true,
		"ABC123.Execute-API.eu-west-1.amazonaws.com.":            true,
		"abc123.execute-api-fips.eu-west-1.amazonaws.com":        true,
		"abc123.execute-api.eu-west-1.api.aws":                   true,
		"abc123.execute-api-fips.eu-west-1.api.aws":              true,
		"abc123.execute-api.dualstack.eu-west-1.amazonaws.com":   true,
		"abc123-vpce-0a1b2c.execute-api.eu-west-1.amazonaws.com": true,
		"abc123.execute-api.us-east-1.amazonaws.com":             true,
		"other1.execute-api.eu-west-1.amazonaws.com":             false,
		"abc1234.execute-api.eu-west-1.amazonaws.com":            false,
		"abc123.example.com":                                     false,
		"api.open-meteo.com":                                     false,
	} {
		if got := api.IsHost(host); got != want {
			t.Errorf("IsHost(%q) = %v, want %v", host, got, want)
		}
	}
}

func TestServesAnswersFromThePublishedRangesOfTheRegion(t *testing.T) {
	api := mustParse(t)
	for addr, want := range map[string]bool{
		"3.248.245.10":         true,  // eu-west-1, 3.248.245.0/24
		"::ffff:108.128.160.7": true,  // the same, mapped into IPv6
		"3.248.244.10":         false, // just outside
		"198.51.100.7":         false,
		"2001:db8::10":         false,
	} {
		if got := api.Serves(netip.MustParseAddr(addr)); got != want {
			t.Errorf("Serves(%s) = %v, want %v", addr, got, want)
		}
	}
	us, err := Parse("abc123.execute-api.us-east-1.amazonaws.com")
	if err != nil {
		t.Fatal(err)
	}
	if us.Serves(netip.MustParseAddr("3.248.245.10")) {
		t.Error("an address of eu-west-1 is served for an API in us-east-1")
	}
}
