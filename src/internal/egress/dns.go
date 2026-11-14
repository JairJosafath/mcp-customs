package egress

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"hash/fnv"
	"net"
	"net/netip"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// A Resolver looks up allowed names for real. *net.Resolver is one.
type Resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
	LookupTXT(ctx context.Context, name string) ([]string, error)
}

// Bounds on DNS.
const (
	maxDNSPacket  = 4096
	lookupTimeout = 5 * time.Second
	fakeTTL       = 60
)

// fakeNet is where faked A answers point: 198.18.0.0/15, set aside for
// testing (RFC 2544), so no real host is ever named. The firewall turns away
// direct connections to it, and records them.
var fakeNet = netip.MustParsePrefix("198.18.0.0/15")

// ServeDNS answers DNS queries on pc until it is closed. Each query becomes
// a dns observation. Allowed names are looked up for real; for any other
// name, A and TXT queries get fake answers, so a server that learns where
// to send its loot from DNS still sends it, and shows where.
func (e *Egress) ServeDNS(pc net.PacketConn) error {
	buf := make([]byte, maxDNSPacket)
	for {
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		reply, ok := e.answerDNS(buf[:n])
		if ok {
			_, _ = pc.WriteTo(reply, addr)
		}
	}
}

// answerDNS answers one query packet; ok is false when it isn't one.
func (e *Egress) answerDNS(packet []byte) ([]byte, bool) {
	var p dnsmessage.Parser
	h, err := p.Start(packet)
	if err != nil || h.Response {
		return nil, false
	}
	q, err := p.Question()
	if err != nil {
		return nil, false
	}
	name := normalHost(q.Name.String())
	answers, rcode, faked := e.lookup(name, q.Type)
	d := DNSDetail{Name: name, Type: typeName(q.Type), Answers: answerStrings(answers), Faked: faked}
	// The name as sent keeps its case, which base64 in a label needs.
	raw := strings.TrimSuffix(q.Name.String(), ".")
	if m := e.match([]byte(raw + "\n" + strings.ReplaceAll(raw, ".", ""))); len(m) > 0 {
		d.Canaries = m
	}
	e.record(KindDNS, d)
	reply, err := buildReply(h, q, answers, rcode)
	if err != nil {
		return nil, false
	}
	return reply, true
}

// lookup answers a query: for real when the name is allowed, faked when not.
func (e *Egress) lookup(name string, t dnsmessage.Type) ([]dnsmessage.ResourceBody, dnsmessage.RCode, bool) {
	if e.isAllowed(name) {
		answers, rcode := e.lookupReal(name, t)
		return answers, rcode, false
	}
	if t == dnsmessage.TypeA {
		addr := FakeAddr(name)
		e.noteFake(addr.String(), name)
		return []dnsmessage.ResourceBody{&dnsmessage.AResource{A: addr.As4()}}, dnsmessage.RCodeSuccess, true
	}
	if t == dnsmessage.TypeTXT {
		return []dnsmessage.ResourceBody{&dnsmessage.TXTResource{TXT: []string{FakeTXT(name)}}}, dnsmessage.RCodeSuccess, true
	}
	// No AAAA, MX or anything else: the name exists, with nothing of that
	// type, so clients fall back to A.
	return nil, dnsmessage.RCodeSuccess, true
}

func (e *Egress) lookupReal(name string, t dnsmessage.Type) ([]dnsmessage.ResourceBody, dnsmessage.RCode) {
	ctx, cancel := context.WithTimeout(context.Background(), lookupTimeout)
	defer cancel()
	var answers []dnsmessage.ResourceBody
	var err error
	isAddr, isTXT := t == dnsmessage.TypeA || t == dnsmessage.TypeAAAA, t == dnsmessage.TypeTXT
	switch {
	case isAddr:
		network := "ip4"
		if t == dnsmessage.TypeAAAA {
			network = "ip6"
		}
		var addrs []netip.Addr
		addrs, err = e.cfg.Resolver.LookupNetIP(ctx, network, name)
		for _, a := range addrs {
			if a.Is4() || a.Is4In6() {
				answers = append(answers, &dnsmessage.AResource{A: a.Unmap().As4()})
			} else {
				answers = append(answers, &dnsmessage.AAAAResource{AAAA: a.As16()})
			}
		}
	case isTXT:
		var txt []string
		txt, err = e.cfg.Resolver.LookupTXT(ctx, name)
		for _, s := range txt {
			answers = append(answers, &dnsmessage.TXTResource{TXT: []string{s}})
		}
	default:
		return nil, dnsmessage.RCodeSuccess
	}
	if dnsErr, ok := errors.AsType[*net.DNSError](err); ok && dnsErr.IsNotFound {
		return nil, dnsmessage.RCodeNameError
	}
	if err != nil {
		return nil, dnsmessage.RCodeServerFailure
	}
	return answers, dnsmessage.RCodeSuccess
}

// FakeAddr is the address a faked A answer gives name: the same each time,
// inside 198.18.0.0/15.
func FakeAddr(name string) netip.Addr {
	h := fnv.New32a()
	_, _ = h.Write([]byte(normalHost(name)))
	base := fakeNet.Addr().As4()
	n := binary.BigEndian.Uint32(base[:]) | (h.Sum32() & 0x1ffff)
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], n)
	return netip.AddrFrom4(b)
}

// FakeTXT is the text a faked TXT answer gives name: a host name under the
// name's own domain, as a configuration record might hold, the same each
// time. Leading labels such as "_cfg" are dropped.
func FakeTXT(name string) string {
	labels := strings.Split(normalHost(name), ".")
	for len(labels) > 0 && strings.HasPrefix(labels[0], "_") {
		labels = labels[1:]
	}
	domain := strings.Join(labels, ".")
	if domain == "" {
		domain = "example.net"
	}
	h := fnv.New32a()
	_, _ = h.Write([]byte(normalHost(name)))
	return "cdn-" + hex.EncodeToString(h.Sum(nil))[:6] + "." + domain
}

func buildReply(h dnsmessage.Header, q dnsmessage.Question, answers []dnsmessage.ResourceBody, rcode dnsmessage.RCode) ([]byte, error) {
	b := dnsmessage.NewBuilder(make([]byte, 0, 512), dnsmessage.Header{
		ID: h.ID, Response: true, Authoritative: true, RecursionDesired: h.RecursionDesired,
		RecursionAvailable: true, RCode: rcode,
	})
	b.EnableCompression()
	if err := b.StartQuestions(); err != nil {
		return nil, err
	}
	if err := b.Question(q); err != nil {
		return nil, err
	}
	if err := b.StartAnswers(); err != nil {
		return nil, err
	}
	for _, a := range answers {
		rh := dnsmessage.ResourceHeader{Name: q.Name, Class: dnsmessage.ClassINET, TTL: fakeTTL}
		var err error
		switch r := a.(type) {
		case *dnsmessage.AResource:
			err = b.AResource(rh, *r)
		case *dnsmessage.AAAAResource:
			err = b.AAAAResource(rh, *r)
		case *dnsmessage.TXTResource:
			err = b.TXTResource(rh, *r)
		}
		if err != nil {
			return nil, err
		}
	}
	return b.Finish()
}

func answerStrings(answers []dnsmessage.ResourceBody) []string {
	out := []string{}
	for _, a := range answers {
		switch r := a.(type) {
		case *dnsmessage.AResource:
			out = append(out, netip.AddrFrom4(r.A).String())
		case *dnsmessage.AAAAResource:
			out = append(out, netip.AddrFrom16(r.AAAA).String())
		case *dnsmessage.TXTResource:
			out = append(out, strings.Join(r.TXT, ""))
		}
	}
	return out
}

// typeName is a query type as people write it: "A", "TXT".
func typeName(t dnsmessage.Type) string {
	return strings.TrimPrefix(t.String(), "Type")
}
