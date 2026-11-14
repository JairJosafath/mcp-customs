package egress

import (
	"encoding/hex"
	"net"
	"slices"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/JairJosafath/mcp-customs/src/internal/canary"
	"github.com/JairJosafath/mcp-customs/src/internal/findings"
)

// dnsMessage builds a DNS message from its header, questions and
// additional TXT records.
func dnsMessage(t *testing.T, h dnsmessage.Header, names []string, extra ...string) []byte {
	t.Helper()
	b := dnsmessage.NewBuilder(nil, h)
	if err := b.StartQuestions(); err != nil {
		t.Fatal(err)
	}
	for _, n := range names {
		if err := b.Question(dnsmessage.Question{Name: dnsmessage.MustNewName(n + "."), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}); err != nil {
			t.Fatal(err)
		}
	}
	if err := b.StartAdditionals(); err != nil {
		t.Fatal(err)
	}
	for _, txt := range extra {
		rh := dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName("x.example."), Class: dnsmessage.ClassINET}
		if err := b.TXTResource(rh, dnsmessage.TXTResource{TXT: []string{txt}}); err != nil {
			t.Fatal(err)
		}
	}
	out, err := b.Finish()
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestEveryDatagramToPort53IsRecordedWithTheCanariesAnywhereInIt(t *testing.T) {
	token := testCanaries.Get(canary.GitHubToken)
	h := hex.EncodeToString([]byte(token))
	query := dnsmessage.Header{ID: 7, RecursionDesired: true}
	for name, tc := range map[string]struct {
		packet   []byte
		answered bool
		encoding findings.Encoding
	}{
		"a payload that isn't DNS": {[]byte("k=" + token), false, findings.Plain},
		"a response packet":        {dnsMessage(t, dnsmessage.Header{ID: 7, Response: true}, []string{"x.example"}, "k="+token), false, findings.Plain},
		"a query with trailing bytes": {
			append(dnsQuery(t, "x.example", dnsmessage.TypeA), "k="+token...), true, findings.Plain,
		},
		"a query with an extra record": {dnsMessage(t, query, []string{"x.example"}, "k="+token), true, findings.Plain},
		// Hex over two labels: on the wire a length byte splits it.
		"the token in a second question": {dnsMessage(t, query, []string{"x.example", h[:40] + "." + h[40:] + ".loot.example"}), true, findings.Hex},
	} {
		t.Run(name, func(t *testing.T) {
			rec := newRecorded()
			e := New(Config{Resolver: fakeResolver{}})
			e.Observe(rec.observe)
			e.SetCanaries(testCanaries)
			if _, ok := e.answerDNS(tc.packet); ok != tc.answered {
				t.Errorf("answered = %v, want %v", ok, tc.answered)
			}
			obs := rec.of(KindDNS)
			if len(obs) != 1 {
				t.Fatalf("dns observations = %+v, want one", obs)
			}
			d, _ := obs[0].(DNSDetail)
			if !slices.Contains(d.Canaries, findings.Match{Canary: canary.GitHubToken, Encoding: tc.encoding}) {
				t.Errorf("canaries = %+v, want the token, %s", d.Canaries, tc.encoding)
			}
			if !tc.answered && d.Unanswered == "" {
				t.Errorf("%+v doesn't say why it wasn't answered", d)
			}
		})
	}
}

func TestADatagramPast4096BytesIsSearchedWhole(t *testing.T) {
	rec := newRecorded()
	e := New(Config{Resolver: fakeResolver{}})
	e.Observe(rec.observe)
	e.SetCanaries(testCanaries)
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	served := make(chan error, 1)
	go func() { served <- e.ServeDNS(pc) }()
	t.Cleanup(func() {
		_ = pc.Close()
		if err := <-served; err != nil {
			t.Error(err)
		}
	})
	client, err := net.Dial("udp", pc.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = client.Close() }()
	packet := append(dnsQuery(t, "x.example", dnsmessage.TypeA), strings.Repeat("x", 60000)+"k="+testCanaries.Get(canary.GitHubToken)...)
	if _, err := client.Write(packet); err != nil {
		t.Fatal(err)
	}
	rec.waitFor(t, func() bool { return len(rec.of(KindDNS)) > 0 })
	if d, _ := rec.of(KindDNS)[0].(DNSDetail); len(d.Canaries) == 0 {
		t.Errorf("a %d-byte datagram = %+v, want the token at its end found", len(packet), d)
	}
}

func TestDatagramsTheDNSSocketDropsAreRecorded(t *testing.T) {
	// A socket whose buffer holds a few datagrams, filled before anything
	// reads it.
	lc := net.ListenConfig{Control: func(_, _ string, c syscall.RawConn) error {
		return setsockopt(c, syscall.SO_RCVBUF, 4096)
	}}
	pc, err := lc.ListenPacket(t.Context(), "udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	client, err := net.Dial("udp4", pc.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = client.Close() }()
	for range 50 {
		_, _ = client.Write(make([]byte, 1000))
	}
	rec := newRecorded()
	e := New(Config{Resolver: fakeResolver{}})
	e.Observe(rec.observe)
	served := make(chan error, 1)
	go func() { served <- e.ServeDNS(pc) }()
	t.Cleanup(func() {
		_ = pc.Close()
		<-served
	})
	rec.waitFor(t, func() bool { return len(rec.of(KindConnect)) > 0 })
	d, _ := rec.of(KindConnect)[0].(ConnectDetail)
	if d.Port != 53 || d.Proto != "udp" || d.Dropped < 1 {
		t.Errorf("dropped = %+v, want udp/53 with a count", d)
	}
	if found := leftAs(t, rec); !hasRule(found, findings.RuleDirectUnrecorded) {
		t.Errorf("findings = %+v, want %s", found, findings.RuleDirectUnrecorded)
	}
}

func TestADNSReaderThatStopsIsRecordedForReview(t *testing.T) {
	rec := newRecorded()
	e := New(Config{Resolver: fakeResolver{}})
	e.Observe(rec.observe)
	if err := e.ServeDNS(failingPacketConn{}); err == nil {
		t.Error("ServeDNS = nil, want the read's error")
	}
	if found := leftAs(t, rec); !hasRule(found, findings.RuleDirectUnrecorded) {
		t.Errorf("findings = %+v, want %s", found, findings.RuleDirectUnrecorded)
	}
}

// failingPacketConn fails every read, as a socket the kernel errors on.
type failingPacketConn struct{ net.PacketConn }

func (failingPacketConn) ReadFrom([]byte) (int, net.Addr, error) {
	return 0, nil, syscall.EIO
}

func TestCanariesSplitInTheRecordsAfterTheQuestionsAreFound(t *testing.T) {
	token := testCanaries.Get(canary.GitHubToken)
	h := hex.EncodeToString([]byte(token))
	// Over two TXT strings, as a length byte splits them on the wire.
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 7})
	_ = b.StartQuestions()
	_ = b.Question(dnsmessage.Question{Name: dnsmessage.MustNewName("x.example."), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET})
	_ = b.StartAdditionals()
	rh := dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName(h[:40] + "." + h[40:] + ".loot.example."), Class: dnsmessage.ClassINET}
	if err := b.TXTResource(rh, dnsmessage.TXTResource{TXT: []string{token[:10], token[10:]}}); err != nil {
		t.Fatal(err)
	}
	packet, err := b.Finish()
	if err != nil {
		t.Fatal(err)
	}
	rec := newRecorded()
	e := New(Config{Resolver: fakeResolver{}})
	e.Observe(rec.observe)
	e.SetCanaries(testCanaries)
	_, _ = e.answerDNS(packet)
	d, _ := rec.of(KindDNS)[0].(DNSDetail)
	for _, enc := range []findings.Encoding{findings.Hex, findings.Plain} {
		if !slices.Contains(d.Canaries, findings.Match{Canary: canary.GitHubToken, Encoding: enc}) {
			t.Errorf("canaries = %+v, want the token, %s", d.Canaries, enc)
		}
	}
}

func TestDropsAreReadFromTheSocketsLineInProcNetUDP(t *testing.T) {
	table := []byte(`   sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops
  795: 0100007F:A1B2 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 4242 2 0000000000000000 17
  796: 0100007F:A1B3 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 4243 2 0000000000000000 0
`)
	if n, ok := dropsIn(table, 4242); !ok || n != 17 {
		t.Errorf("dropsIn(4242) = %d, %v; want 17", n, ok)
	}
	if _, ok := dropsIn(table, 9); ok {
		t.Error("an inode not in the table was found")
	}
}
