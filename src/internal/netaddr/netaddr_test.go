package netaddr

import (
	"net/netip"
	"testing"
)

func TestPublicRefusesAddressesInsideANetwork(t *testing.T) {
	for addr, want := range map[string]bool{
		"198.51.100.7":       true,
		"2001:db8::1":        true,
		"127.0.0.1":          false,
		"::1":                false,
		"169.254.169.254":    false,
		"fd00:ec2::254":      false,
		"10.1.2.3":           false,
		"172.16.0.1":         false,
		"192.168.1.1":        false,
		"100.64.0.1":         false,
		"0.0.0.0":            false,
		"::":                 false,
		"fe80::1":            false,
		"::ffff:127.0.0.1":   false,
		"::127.0.0.1":        false,
		"64:ff9b::a9fe:a9fe": false,
		"2002:a9fe:a9fe::1":  false,
		"2001:0:a9fe:a9fe::": false,
		"fec0::1":            false,
	} {
		if got := Public(netip.MustParseAddr(addr)); got != want {
			t.Errorf("Public(%s) = %v, want %v", addr, got, want)
		}
	}
	if Public(netip.Addr{}) {
		t.Error("Public(the zero address) = true, want false")
	}
}
