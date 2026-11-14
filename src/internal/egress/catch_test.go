package egress

import (
	"net"
	"net/netip"
	"slices"
	"testing"

	"github.com/JairJosafath/mcp-customs/src/internal/canary"
	"github.com/JairJosafath/mcp-customs/src/internal/findings"
)

func TestADirectTCPConnectionsPayloadIsSearchedForCanaries(t *testing.T) {
	rec := newRecorded()
	e := New(Config{})
	e.Observe(rec.observe)
	e.SetCanaries(testCanaries)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	headed := netip.MustParseAddrPort("203.0.113.9:9997")
	served := make(chan error, 1)
	go func() {
		served <- e.ServeCatch(l, func(net.Conn) (netip.AddrPort, error) { return headed, nil })
	}()
	t.Cleanup(func() {
		_ = l.Close()
		if err := <-served; err != nil {
			t.Error(err)
		}
	})
	conn, err := net.DialTCP("tcp", nil, net.TCPAddrFromAddrPort(netip.MustParseAddrPort(l.Addr().String())))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	if _, err := conn.Write([]byte("k=" + testCanaries.Get(canary.GitHubToken))); err != nil {
		t.Fatal(err)
	}
	if err := conn.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	rec.waitFor(t, func() bool { return len(rec.of(KindConnect)) > 0 })
	d, _ := rec.of(KindConnect)[0].(ConnectDetail)
	if d.Address != "203.0.113.9" || d.Port != 9997 || !slices.Contains(d.Canaries, findings.Match{Canary: canary.GitHubToken, Encoding: findings.Plain}) {
		t.Errorf("connect = %+v, want 203.0.113.9:9997 with the token", d)
	}
}
