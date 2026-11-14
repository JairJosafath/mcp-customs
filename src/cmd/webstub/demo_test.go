package main

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/aws/aws-lambda-go/events"

	"github.com/JairJosafath/mcp-customs/src/internal/web"
)

// apiCheck is the part of GET /api/checks/<id> the tests read.
type apiCheck struct {
	Status   string `json:"status"`
	Verdict  string `json:"verdict"`
	Findings []struct {
		Rule     string `json:"rule"`
		Evidence string `json:"evidence"`
	} `json:"findings"`
	InstallSpec *struct {
		Ref string `json:"ref"`
	} `json:"installSpec"`
}

func serve(t *testing.T, h http.Handler, method, path, form string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), method, path, strings.NewReader(form))
	if form != "" {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// settle submits kind and ref through the form and reads the check until
// it stops running.
func settle(t *testing.T, h http.Handler, kind, ref string) (string, apiCheck) {
	t.Helper()
	rec := serve(t, h, http.MethodPost, "/checks", url.Values{"kind": {kind}, "ref": {ref}}.Encode())
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("POST /checks answered %d: %s", rec.Code, rec.Body)
	}
	id := strings.TrimPrefix(rec.Header().Get("Location"), "/checks/")
	for range 50 {
		if c := read(t, h, id); c.Status != "running" {
			return id, c
		}
	}
	t.Fatalf("check %s of %s still runs after 50 reads", id, ref)
	return "", apiCheck{}
}

func newStub() http.Handler {
	d := newDemo()
	return adapter{web.New(web.Deps{
		Checks: d, Reports: d, Checker: d, ReviewerKey: []byte("k"), NewID: web.NewCheckID,
		Log: slog.New(slog.DiscardHandler),
	})}
}

func TestEachDemoServerEndsAsItsScriptSays(t *testing.T) {
	tests := []struct {
		name, ref, decision, verdict, finding string
		installSpec                           bool
	}{
		{"the weather server waits, and a person blocks it", "weather-mcp@1.0.0", "block", "block", "ssh-private-key, base64", false},
		{"the mail server's v1.0.0 passes alone", "mail-mcp@1.0.0", "", "pass", "", true},
		{"the mail server's v1.0.1 waits, and a person blocks it", "mail-mcp@1.0.1", "block", "block", "email, plain", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newStub()
			id, c := settle(t, h, "npm", tt.ref)
			if tt.decision != "" {
				if c.Status != "waiting" {
					t.Fatalf("status = %q, want waiting", c.Status)
				}
				form := url.Values{"decision": {tt.decision}, "reviewerKey": {"k"}}.Encode()
				if rec := serve(t, h, http.MethodPost, "/checks/"+id+"/decision", form); rec.Code != http.StatusSeeOther {
					t.Fatalf("the decision answered %d: %s", rec.Code, rec.Body)
				}
				c = read(t, h, id)
			}
			if c.Status != "done" || c.Verdict != tt.verdict {
				t.Fatalf("status, verdict = %q, %q; want done, %q", c.Status, c.Verdict, tt.verdict)
			}
			if tt.finding != "" && !hasFinding(c, "canary-left", tt.finding) {
				t.Errorf("findings = %+v, want canary-left %q", c.Findings, tt.finding)
			}
			if (c.InstallSpec != nil) != tt.installSpec {
				t.Errorf("install spec = %+v, want one: %v", c.InstallSpec, tt.installSpec)
			}
		})
	}
}

// read is check id as GET /api/checks/<id> answers it.
func read(t *testing.T, h http.Handler, id string) apiCheck {
	t.Helper()
	var c apiCheck
	if err := json.Unmarshal(serve(t, h, http.MethodGet, "/api/checks/"+id, "").Body.Bytes(), &c); err != nil {
		t.Fatal(err)
	}
	return c
}

func hasFinding(c apiCheck, rule, evidence string) bool {
	for _, f := range c.Findings {
		if f.Rule == rule && f.Evidence == evidence {
			return true
		}
	}
	return false
}

func TestTheAdapterPassesMethodPathHeadersAndBodyAsAPIGatewayWould(t *testing.T) {
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/checks/a%2Fb?x=1", strings.NewReader("k=v"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	got := toEvent(req, []byte("k=v"))
	want := events.APIGatewayV2HTTPRequest{RawPath: "/checks/a%2Fb", RawQueryString: "x=1", Body: "k=v"}
	if got.RawPath != want.RawPath || got.RawQueryString != want.RawQueryString || got.Body != want.Body ||
		got.RequestContext.HTTP.Method != http.MethodPost || got.Headers["content-type"] != "application/x-www-form-urlencoded" {
		t.Errorf("event = %+v", got)
	}
}
