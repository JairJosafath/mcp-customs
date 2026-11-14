package ownapi

import (
	"net/netip"
	"strings"
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

func TestValidHostAcceptsOnlyPlainASCIIHostNames(t *testing.T) {
	long := strings.Repeat("a", 63)
	for host, ok := range map[string]bool{
		apiHost:                true,
		"API.Weather.example.": true,
		"1password.com":        true,
		"x.0xdead.io":          true,
		"123.example":          true,
		long + ".example":      true,
		"abc\u00ad123.execute-api.us-east-1.amazonaws.com":               false, // a soft hyphen
		"abc123\u3002execute-api\u3002us-east-1\u3002amazonaws\u3002com": false, // ideographic full stops
		"\uff41bc123.execute-api.us-east-1.amazonaws.com":                false, // a fullwidth a
		"xn--abc123-dja.execute-api.us-east-1.amazonaws.com":             false, // punycode
		"abc123.XN--p1ai":                false,
		"":                               false,
		".":                              false,
		"a..example":                     false,
		".example":                       false,
		"example..":                      false,
		"-a.example":                     false,
		"a-.example":                     false,
		"a_b.example":                    false,
		"a b.example":                    false,
		"api.example:443":                false,
		"user@api.example":               false,
		long + "a.example":               false,
		strings.Repeat("a.", 127) + "co": false,
		"3.248.245.10":                   false,
		"127.1":                          false,
		"2130706433":                     false,
		"0x7f.0.0.1":                     false,
		"0x7f000001":                     false,
		"2001:db8::10":                   false,
		"[2001:db8::10]":                 false,
	} {
		if err := ValidHost(host); (err == nil) != ok {
			t.Errorf("ValidHost(%q) = %v, want valid %v", host, err, ok)
		}
	}
}

func TestCanonicalReadsAnIPv4AddressEmbeddedInIPv6AsItself(t *testing.T) {
	for in, want := range map[string]string{
		"::ffff:3.248.245.10":   "3.248.245.10",
		"::3.248.245.10":        "3.248.245.10",
		"64:ff9b::3.248.245.10": "3.248.245.10",
		"3.248.245.10":          "3.248.245.10",
		"::1":                   "::1",
		"::":                    "::",
		"2001:db8::10":          "2001:db8::10",
		"fe80::1%eth0":          "fe80::1",
	} {
		if got := Canonical(netip.MustParseAddr(in)); got != netip.MustParseAddr(want) {
			t.Errorf("Canonical(%s) = %s, want %s", in, got, want)
		}
	}
	api := mustParse(t)
	for _, in := range []string{"::3.248.245.10", "64:ff9b::3.248.245.10"} {
		if !api.Serves(netip.MustParseAddr(in)) {
			t.Errorf("Serves(%s) = false, want the embedded address refused", in)
		}
	}
	if got := api.Names(); len(got) != 2 || got[0] != apiHost || got[1] != "abc123.execute-api.eu-west-1.api.aws" {
		t.Errorf("Names = %v, want the standard and the dual-stack name", got)
	}
}
