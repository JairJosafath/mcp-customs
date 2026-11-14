package egress

import (
	"encoding/hex"
	"net"
	"slices"
	"strings"
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
