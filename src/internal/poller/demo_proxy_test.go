package poller

import (
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/JairJosafath/mcp-customs/src/internal/demoproxy"
	"github.com/JairJosafath/mcp-customs/src/internal/store"
)

// demoProxy serves the demo proxy's files as a deploy leaves them with the
// mail demo at version, under /goproxy/ as the stack does.
func demoProxy(t *testing.T, version string) *httptest.Server {
	t.Helper()
	files, err := demoproxy.Files(os.DirFS("../.."), map[string]string{"mail": version, "weather": "v1.0.0"})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, ok := files[strings.TrimPrefix(r.URL.Path, "/goproxy/")]
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// publicProxy answers every module's @latest with v2.0.0 and keeps the
// paths it was asked.
type publicProxy struct {
	mu    sync.Mutex
	asked []string
}

func (p *publicProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p.mu.Lock()
	p.asked = append(p.asked, r.URL.Path)
	p.mu.Unlock()
	_, _ = w.Write([]byte(`{"Version":"v2.0.0"}`))
}

func TestThePollerSeesTheMailDemosV101OnceItIsPublishedAndStartsTheRecheck(t *testing.T) {
	mail := demoproxy.ModulePrefix + "/mail"
	public := &publicProxy{}
	publicSrv := httptest.NewServer(public)
	t.Cleanup(publicSrv.Close)
	approved := store.Approved{Kind: "go", Name: mail, Version: "v1.0.0", CheckID: "c0", ToolListHash: "tools", Polled: "v1.0.0"}
	approvals := &memoryApprovals{items: []store.Approved{approved}}
	starter := &recordingStarter{}

	for _, version := range []string{"v1.0.0", "v1.0.1"} {
		demo := demoProxy(t, version)
		registry := NewHTTPRegistry(http.DefaultClient, Registries{Go: demo.URL + "/goproxy," + publicSrv.URL})
		if _, err := Poll(t.Context(), Deps{Approvals: approvals, Registry: registry, Checker: starter, Log: discard()}); err != nil {
			t.Fatal(err)
		}
	}
	want := []Event{{
		CheckID:    RecheckID("go", mail, "v1.0.1"),
		Submission: store.Submission{Kind: "go", Ref: mail + "@v1.0.1"},
		Recheck:    Link{CheckID: "c0", Ref: mail + "@v1.0.0", ToolListHash: "tools"},
	}}
	if got := starter.started(); !reflect.DeepEqual(got, want) {
		t.Errorf("started %+v, want only v1.0.1's re-check, after it was published", got)
	}
	if len(public.asked) != 0 {
		t.Errorf("the public proxy was asked %v for a demo module", public.asked)
	}
}

func TestAModuleTheDemoProxyLacksIsAskedOfTheNextProxy(t *testing.T) {
	public := &publicProxy{}
	publicSrv := httptest.NewServer(public)
	t.Cleanup(publicSrv.Close)
	registry := NewHTTPRegistry(http.DefaultClient, Registries{Go: demoProxy(t, "v1.0.1").URL + "/goproxy," + publicSrv.URL})
	got, err := registry.Latest(t.Context(), "go", "github.com/Example/mcp")
	if err != nil || got != "v2.0.0" {
		t.Errorf("latest %q, %v; want the public proxy's v2.0.0", got, err)
	}
	if want := []string{"/github.com/!example/mcp/@latest"}; !reflect.DeepEqual(public.asked, want) {
		t.Errorf("the public proxy was asked %v, want %v", public.asked, want)
	}
}
