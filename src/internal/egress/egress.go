// Package egress is the sandbox's egress proxy: every connection the server
// under test makes goes through it. It answers DNS, faking names it doesn't
// know so a second stage still shows itself; it intercepts TLS with its own
// certificate authority; it passes requests to allowed hosts through and
// answers the rest with a fake 200; and it searches every request for the
// run's canaries. What it sees, it reports as dns, connect and http
// observations (docs/contracts.md). The firewall rules that make the
// server's traffic come here are in firewall.go.
package egress

import (
	"net/http"
	"slices"
	"strings"
	"sync"

	"github.com/JairJosafath/mcp-customs/src/internal/canary"
	"github.com/JairJosafath/mcp-customs/src/internal/findings"
)

// The kinds of observation the egress proxy makes.
const (
	KindDNS     = "dns"
	KindConnect = "connect"
	KindHTTP    = "http"
)

// An Observer is told each thing the proxy sees, as an observation's kind
// and detail. It must be safe for concurrent use.
type Observer func(kind string, detail any)

// DNSDetail is a dns observation's detail: a query and what it was answered.
type DNSDetail struct {
	Name    string   `json:"name"`
	Type    string   `json:"type"`
	Answers []string `json:"answers"`
	// Faked is true when the answer was made up: the name isn't allowed.
	Faked bool `json:"faked"`
	// Canaries are those found in the name, as written or with its dots
	// taken out, as a key spread over labels would be.
	Canaries []findings.Match `json:"canaries,omitempty"`
}

// ConnectDetail is a connect observation's detail: a tunnel asked of the
// proxy, or direct traffic the firewall turned away.
type ConnectDetail struct {
	// Host is the name asked for, or, for direct traffic, the name a faked
	// DNS answer gave the address, when there was one.
	Host string `json:"host,omitempty"`
	// Address is where direct traffic was headed.
	Address string `json:"address,omitempty"`
	Port    int    `json:"port"`
	// Proto is the protocol of direct traffic: tcp, udp, icmp, icmpv6, or
	// the IP protocol number.
	Proto string `json:"proto,omitempty"`
	// Via is "proxy" for a CONNECT tunnel, "direct" for traffic that
	// ignored the proxy.
	Via string `json:"via"`
	// Intercepted is true when the proxy read the tunnel's TLS; false when
	// the client refused its certificate or spoke something else.
	Intercepted bool `json:"intercepted"`
	// Allowed is true when a tunnel's host is on the allowlist.
	Allowed bool `json:"allowed"`
	// Refused is true when the traffic was turned away.
	Refused bool `json:"refused"`
	// Canaries are those found in a refused packet's payload.
	Canaries []findings.Match `json:"canaries,omitempty"`
	// More is true on the last direct observation a run records: later
	// refused packets are refused but not recorded.
	More bool `json:"more,omitempty"`
}

// HTTPDetail is an http observation's detail: one request, and the canaries
// found in it, each with its encoding. The body itself is not kept.
type HTTPDetail struct {
	Method   string           `json:"method"`
	Host     string           `json:"host"`
	Path     string           `json:"path"`
	Allowed  bool             `json:"allowed"`
	Canaries []findings.Match `json:"canaries"`
	// Unscanned says why part of the body was not searched: it was over
	// 8 MiB, or in an encoding the proxy can't decode. Empty when all of it
	// was searched.
	Unscanned string `json:"unscanned,omitempty"`
}

// Config is what the proxy needs.
type Config struct {
	// CA signs the certificates the proxy shows the server.
	CA *CA
	// Upstream sends allowed requests on, to the real host.
	Upstream http.RoundTripper
	// Resolver answers DNS queries for allowed names.
	Resolver Resolver
	// Allow are the hosts allowed from the start.
	Allow []string
	// InstallAllow are the hosts allowed only while an install runs, such
	// as the package registries (RegistryHosts).
	InstallAllow []string
	// ServerEnv is what the server's environment needs to go through the
	// proxy and trust the CA (see Env).
	ServerEnv []string
}

// Egress is the proxy for one run. It is safe for concurrent use.
type Egress struct {
	cfg Config

	mu         sync.Mutex
	allowed    map[string]bool
	install    map[string]bool
	installing bool
	canaries   canary.Set
	observe    Observer
	fakes      map[string]string
	direct     int
}

// New makes the proxy. Nothing is observed until Observe names an observer.
func New(cfg Config) *Egress {
	e := &Egress{cfg: cfg, allowed: map[string]bool{}, install: map[string]bool{}, fakes: map[string]string{}, observe: func(string, any) {}}
	e.Allow(cfg.Allow...)
	for _, h := range cfg.InstallAllow {
		if h = normalHost(h); h != "" {
			e.install[h] = true
		}
	}
	return e
}

// Installing says whether an install runs: while it does, InstallAllow's
// hosts are allowed too. The server itself, started after, can't reach them.
func (e *Egress) Installing(on bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.installing = on
}

// Env is what the server's environment needs to go through the proxy.
func (e *Egress) Env() []string {
	return slices.Clone(e.cfg.ServerEnv)
}

// Observe names who is told what the proxy sees.
func (e *Egress) Observe(o Observer) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.observe = o
}

// SetCanaries names the run's canaries, which every request is searched for.
func (e *Egress) SetCanaries(c canary.Set) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.canaries = slices.Clone(c)
}

// Allow adds hosts to the allowlist and answers the allowlist now in force,
// sorted. A host is a DNS name, matched exactly, in any case.
func (e *Egress) Allow(hosts ...string) []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, h := range hosts {
		if h = normalHost(h); h != "" {
			e.allowed[h] = true
		}
	}
	list := make([]string, 0, len(e.allowed))
	for h := range e.allowed {
		list = append(list, h)
	}
	slices.Sort(list)
	return list
}

func (e *Egress) isAllowed(host string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	h := normalHost(host)
	return e.allowed[h] || (e.installing && e.install[h])
}

func (e *Egress) record(kind string, detail any) {
	e.mu.Lock()
	o := e.observe
	e.mu.Unlock()
	o(kind, detail)
}

func (e *Egress) match(data []byte) []findings.Match {
	e.mu.Lock()
	c := e.canaries
	e.mu.Unlock()
	m := findings.MatchCanaries(data, c)
	if m == nil {
		m = []findings.Match{}
	}
	return m
}

// maxDirect bounds the direct traffic one run records, so a flood of
// refused packets can't flood the observations.
const maxDirect = 1000

// recordDirect records refused direct traffic, up to maxDirect times.
func (e *Egress) recordDirect(d ConnectDetail) {
	e.mu.Lock()
	e.direct++
	n := e.direct
	e.mu.Unlock()
	if n > maxDirect {
		return
	}
	d.More = n == maxDirect
	e.record(KindConnect, d)
}

// noteFake remembers which name a faked address was given for, so a direct
// connection to it can be named.
func (e *Egress) noteFake(addr, name string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.fakes[addr] = name
}

func (e *Egress) fakeName(addr string) string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.fakes[addr]
}

// normalHost is a host name as the allowlist keeps it: lower case, with no
// trailing dot.
func normalHost(h string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(h)), ".")
}

// RegistryHosts are the package registries an install reaches: allowed
// while it runs (Config.InstallAllow), and still observed.
var RegistryHosts = []string{
	"proxy.golang.org", "sum.golang.org", "storage.googleapis.com",
	"registry.npmjs.org",
	"pypi.org", "files.pythonhosted.org",
}
