package egress

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash/fnv"
	"net"
	"net/netip"
	"os"
	"slices"
	"strconv"
	"strings"
	"syscall"
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
	// maxDNSPacket holds the largest UDP datagram, so each is read whole.
	maxDNSPacket  = 64 << 10
	lookupTimeout = 5 * time.Second
	fakeTTL       = 60
)

// fakeNet is where faked A answers point: 198.18.0.0/15, set aside for
// testing (RFC 2544), so no real host is ever named. The firewall turns away
// direct connections to it, and records them.
var fakeNet = netip.MustParsePrefix("198.18.0.0/15")

// ServeDNS answers DNS queries on pc until it is closed. Each datagram
// becomes a dns observation, query or not, searched whole for canaries.
// Allowed names are looked up for real; for any other name, A and TXT
// queries get fake answers, so a server that learns where to send its loot
// from DNS still sends it, and shows where. When pc is a UDP socket, the
// datagrams the kernel dropped unread are recorded too, by its count; and
// if ServeDNS stops early, it records that it stopped.
func (e *Egress) ServeDNS(pc net.PacketConn) error {
	buf := make([]byte, maxDNSPacket)
	inode, counted := socketInode(pc)
	var drops uint64
	for {
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			e.recordStopped(dnsSocket, err.Error())
			return fmt.Errorf("read DNS: %w", err)
		}
		// A drop needs a full queue, so a datagram read after it always
		// comes: checking after each read misses none.
		if counted {
			if total, ok := udpDrops(inode); ok && total > drops {
				e.recordDropped(dnsSocket, int(total-drops)) //nolint:gosec // a count of datagrams, far below int's range
				drops = total
			}
		}
		reply, ok := e.answerDNS(buf[:n])
		if ok {
			_, _ = pc.WriteTo(reply, addr)
		}
	}
}

// dnsSocket is how observations of the DNS socket name it.
var dnsSocket = ConnectDetail{Proto: "udp", Port: 53}

// socketInode is the inode of pc's socket, which names it in
// /proc/net/udp, when it is one.
func socketInode(pc net.PacketConn) (uint64, bool) {
	sc, ok := pc.(syscall.Conn)
	if !ok {
		return 0, false
	}
	raw, err := sc.SyscallConn()
	if err != nil {
		return 0, false
	}
	var st syscall.Stat_t
	var serr error
	if err := raw.Control(func(fd uintptr) { serr = syscall.Fstat(int(fd), &st) }); err != nil || serr != nil {
		return 0, false
	}
	return st.Ino, true
}

// udpDrops is the kernel's count of datagrams the UDP socket of inode has
// dropped, from /proc/net/udp.
func udpDrops(inode uint64) (uint64, bool) {
	table, err := os.ReadFile("/proc/net/udp")
	if err != nil {
		return 0, false
	}
	return dropsIn(table, inode)
}

// dropsIn reads the drops column of inode's line in a /proc/net/udp table.
func dropsIn(table []byte, inode uint64) (uint64, bool) {
	want := strconv.FormatUint(inode, 10)
	for line := range strings.SplitSeq(string(table), "\n") {
		f := strings.Fields(line)
		// sl local rem st tx:rx tr:when retrnsmt uid timeout inode ref pointer drops
		if len(f) >= 13 && f[9] == want {
			n, err := strconv.ParseUint(f[12], 10, 64)
			return n, err == nil
		}
	}
	return 0, false
}

// answerDNS records one datagram and answers its first question; ok is
// false when it isn't a query.
func (e *Egress) answerDNS(packet []byte) ([]byte, bool) {
	var p dnsmessage.Parser
	h, err := p.Start(packet)
	var questions []dnsmessage.Question
	var why string
	switch {
	case err != nil:
		why = "not a DNS message"
	case h.Response:
		why = "a DNS response, not a query"
	default:
		questions = allQuestions(&p)
		if len(questions) == 0 {
			why = "a DNS message with no question"
		}
	}
	var texts []string
	for _, q := range questions {
		texts = append(texts, q.Name.String())
	}
	if err == nil {
		texts = append(texts, recordTexts(&p)...)
	}
	d := DNSDetail{Answers: []string{}, Unanswered: why}
	if m := e.match(searched(packet, texts)); len(m) > 0 {
		d.Canaries = m
	}
	if why != "" {
		e.record(KindDNS, d)
		return nil, false
	}
	q := questions[0]
	d.Name, d.Type = normalHost(q.Name.String()), typeName(q.Type)
	answers, rcode, faked := e.lookup(d.Name, q.Type)
	d.Answers, d.Faked = answerStrings(answers), faked
	e.record(KindDNS, d)
	reply, err := buildReply(h, q, answers, rcode)
	if err != nil {
		return nil, false
	}
	return reply, true
}

// allQuestions are the questions p holds, up to the first it can't parse.
func allQuestions(p *dnsmessage.Parser) []dnsmessage.Question {
	var out []dnsmessage.Question
	for {
		q, err := p.Question()
		if err != nil {
			return out
		}
		out = append(out, q)
	}
}

// recordTexts are the owner names and TXT strings of every record after
// the questions, up to the first p can't parse: each searched with its
// pieces joined, as a key spread over labels or strings would be.
func recordTexts(p *dnsmessage.Parser) []string {
	var out []string
	sections := []func() (dnsmessage.Resource, error){p.Answer, p.Authority, p.Additional}
	for _, next := range sections {
		for {
			r, err := next()
			if errors.Is(err, dnsmessage.ErrSectionDone) {
				break
			}
			if err != nil {
				return out
			}
			out = append(out, r.Header.Name.String())
			if txt, ok := r.Body.(*dnsmessage.TXTResource); ok {
				out = append(out, strings.Join(txt.TXT, ""))
			}
		}
	}
	return out
}

// searched is what of a datagram is searched for canaries: all of it, and
// each name and text in it as sent, which keeps its case for base64 in a
// label, and with its dots taken out.
func searched(packet []byte, texts []string) []byte {
	out := slices.Clone(packet)
	for _, t := range texts {
		raw := strings.TrimSuffix(t, ".")
		out = append(out, "\n"+raw+"\n"+strings.ReplaceAll(raw, ".", "")...)
	}
	return out
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
