package web

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/aws/aws-lambda-go/events"
)

func TestAnswerServesTheHomePage(t *testing.T) {
	resp := newFixture(t).answer(t, request(http.MethodGet, "/", "GET /"))
	if resp.StatusCode != http.StatusOK {
		t.Errorf("GET / = %d %s", resp.StatusCode, resp.Body)
	}
	if got := resp.Headers["content-type"]; got != "text/html; charset=utf-8" {
		t.Errorf("content-type = %q", got)
	}
	for _, want := range []string{"<!doctype html>", "<title>MCP Customs</title>", `<form method="post" action="/checks">`} {
		if !strings.Contains(resp.Body, want) {
			t.Errorf("the page lacks %q: %s", want, resp.Body)
		}
	}
}

func TestAnswerServesHealthAsJSON(t *testing.T) {
	resp := newFixture(t).answer(t, request(http.MethodGet, "/api/health", "GET /api/{proxy+}"))
	if resp.StatusCode != http.StatusOK || resp.Body != `{"status":"ok"}` {
		t.Errorf("GET /api/health = %d %s", resp.StatusCode, resp.Body)
	}
	if got := resp.Headers["content-type"]; got != "application/json" {
		t.Errorf("content-type = %q", got)
	}
}

func TestAnswerAnswersNotFoundAsJSON(t *testing.T) {
	for name, tc := range map[string]struct {
		req  *events.APIGatewayV2HTTPRequest
		want string
	}{
		"an unknown API route": {request(http.MethodGet, "/api/nothing", "GET /api/{proxy+}"), "No API route GET /api/nothing."},
		"another method":       {request(http.MethodPost, "/api/health", "POST /api/{proxy+}"), "No API route POST /api/health."},
		"an unknown page":      {request(http.MethodGet, "/nothing", "$default"), "No page GET /nothing."},
		"a path of 100 characters, whole": {
			request(http.MethodGet, "/"+strings.Repeat("a", 99), "$default"),
			"No page GET /" + strings.Repeat("a", 99) + ".",
		},
		"a long API path, cut to 100 characters": {
			request(http.MethodGet, "/api/"+strings.Repeat("a", 10000), "GET /api/{proxy+}"),
			"No API route GET /api/" + strings.Repeat("a", 94) + "….",
		},
		"a long page path, cut between characters, not bytes": {
			request(http.MethodGet, "/"+strings.Repeat("é", 200), "$default"),
			"No page GET /" + strings.Repeat("é", 98) + "….",
		},
	} {
		resp := newFixture(t).answer(t, tc.req)
		var body struct {
			Message string `json:"message"`
		}
		if err := json.Unmarshal([]byte(resp.Body), &body); err != nil {
			t.Fatalf("%s: the body %q is not JSON: %v", name, resp.Body, err)
		}
		if resp.StatusCode != http.StatusNotFound || body.Message != tc.want {
			t.Errorf("%s: %d %q, want 404 %q", name, resp.StatusCode, body.Message, tc.want)
		}
	}
}

func TestAnswerSetsAStrictContentSecurityPolicyOnEveryAnswer(t *testing.T) {
	f := newFixture(t)
	for _, req := range []*events.APIGatewayV2HTTPRequest{
		request(http.MethodGet, "/", "GET /"),
		request(http.MethodGet, "/checks/nothing", "GET /checks/{id}"),
		request(http.MethodGet, "/api/health", "GET /api/{proxy+}"),
		request(http.MethodGet, "/nothing", "$default"),
		jsonPost(`{`),
	} {
		resp := f.answer(t, req)
		csp := resp.Headers["content-security-policy"]
		for _, want := range []string{"default-src 'none'", "script-src 'self'", "style-src 'self'", "frame-ancestors 'none'", "form-action 'self'"} {
			if !strings.Contains(csp, want) {
				t.Errorf("%s: content-security-policy %q lacks %q", req.RawPath, csp, want)
			}
		}
		if strings.Contains(csp, "unsafe") {
			t.Errorf("%s: content-security-policy %q allows something unsafe", req.RawPath, csp)
		}
		if resp.Headers["x-content-type-options"] != "nosniff" || resp.Headers["referrer-policy"] != "no-referrer" {
			t.Errorf("%s: headers %v", req.RawPath, resp.Headers)
		}
	}
}

func TestAnswerServesTheScriptAndStyleSheetFromItsOwnOrigin(t *testing.T) {
	f := newFixture(t)
	for path, want := range map[string]string{
		"/static/check.js":  "text/javascript; charset=utf-8",
		"/static/style.css": "text/css; charset=utf-8",
	} {
		resp := f.answer(t, request(http.MethodGet, path, "GET /static/{file}"))
		if resp.StatusCode != http.StatusOK || resp.Headers["content-type"] != want || resp.Body == "" {
			t.Errorf("GET %s = %d %q", path, resp.StatusCode, resp.Headers["content-type"])
		}
	}
	if resp := f.answer(t, request(http.MethodGet, "/static/other.js", "GET /static/{file}")); resp.StatusCode != http.StatusNotFound {
		t.Errorf("GET /static/other.js = %d, want 404", resp.StatusCode)
	}
}

func TestAnswerHidesAFailuresDetailsBehindA500(t *testing.T) {
	f := newFixture(t)
	f.checks.err = errors.New("dynamodb: AccessDenied for arn:aws:iam::123456789012:role/x")
	resp := f.answer(t, request(http.MethodGet, "/api/checks/c1", "GET /api/{proxy+}"))
	if resp.StatusCode != http.StatusInternalServerError || strings.Contains(resp.Body, "AccessDenied") {
		t.Errorf("= %d %s, want 500 without the error", resp.StatusCode, resp.Body)
	}
}
