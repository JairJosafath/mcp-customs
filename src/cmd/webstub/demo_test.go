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
	Status    string `json:"status"`
	Verdict   string `json:"verdict"`
	DecidedBy string `json:"decidedBy"`
	Steps     []struct {
		Name string `json:"name"`
	} `json:"steps"`
	RecheckOf *struct {
		CheckID string `json:"checkId"`
	} `json:"recheckOf"`
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
	return id, settled(t, h, id)
}

// settled reads check id until it stops running.
func settled(t *testing.T, h http.Handler, id string) apiCheck {
	t.Helper()
	for range 50 {
		if c := read(t, h, id); c.Status != "running" {
			return c
		}
	}
	t.Fatalf("check %s still runs after 50 reads", id)
	return apiCheck{}
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
				c = settled(t, h, id)
				if c.DecidedBy != "a person blocked" {
					t.Errorf("decidedBy = %q, want the Checker's \"a person blocked\"", c.DecidedBy)
				}
				if names := stepNames(c); !strings.HasSuffix(names, "ask_human verdict") {
					t.Errorf("steps = %s, want ask_human then verdict after the decision", names)
				}
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

func stepNames(c apiCheck) string {
	names := make([]string, len(c.Steps))
	for i, s := range c.Steps {
		names[i] = s.Name
	}
	return strings.Join(names, " ")
}

func TestV101AfterAnApprovedV100IsARecheckLinkedToIt(t *testing.T) {
	h := newStub()
	approvedID, _ := settle(t, h, "npm", "mail-mcp@1.0.0")
	_, c := settle(t, h, "npm", "mail-mcp@1.0.1")
	if c.RecheckOf == nil || c.RecheckOf.CheckID != approvedID {
		t.Errorf("recheckOf = %+v, want check %s", c.RecheckOf, approvedID)
	}
	if !strings.Contains(stepNames(c), "scan compare write_probes") {
		t.Errorf("steps = %s, want compare after scan, as the Checker writes it", stepNames(c))
	}
}

func TestAStalledCheckNeverSettles(t *testing.T) {
	h := newStub()
	rec := serve(t, h, http.MethodPost, "/checks", url.Values{"kind": {"npm"}, "ref": {"stall-mcp@1.0.0"}}.Encode())
	id := strings.TrimPrefix(rec.Header().Get("Location"), "/checks/")
	for range 20 {
		if c := read(t, h, id); c.Status != "running" {
			t.Fatalf("status = %q, want running for ever", c.Status)
		}
	}
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
