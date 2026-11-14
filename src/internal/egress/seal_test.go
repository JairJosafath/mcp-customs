package egress

import (
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

// heldUpstream holds every request it is sent until the request's context
// ends, and says when one arrives.
type heldUpstream struct {
	arrived chan struct{}
	cut     chan struct{}
}

func (h *heldUpstream) RoundTrip(r *http.Request) (*http.Response, error) {
	h.arrived <- struct{}{}
	<-r.Context().Done()
	close(h.cut)
	return nil, r.Context().Err()
}

func TestSealCutsARequestBeingSentOn(t *testing.T) {
	ca := newCA(t)
	up := &heldUpstream{arrived: make(chan struct{}, 1), cut: make(chan struct{})}
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
	<-up.arrived
	e.Seal()
	<-up.cut
	if status := <-done; status != http.StatusBadGateway {
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
