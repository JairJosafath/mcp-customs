package web

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"testing"

	"github.com/aws/aws-lambda-go/events"
)

var noLog = slog.New(slog.DiscardHandler)

// request is an HTTP API (payload 2.0) event for method and path, as the
// stack's routes send it.
func request(method, path, routeKey string) *events.APIGatewayV2HTTPRequest {
	return &events.APIGatewayV2HTTPRequest{
		Version:  "2.0",
		RouteKey: routeKey,
		RawPath:  path,
		RequestContext: events.APIGatewayV2HTTPRequestContext{
			RequestID: "request-1",
			RouteKey:  routeKey,
			Stage:     "$default",
			HTTP:      events.APIGatewayV2HTTPRequestContextHTTPDescription{Method: method, Path: path},
		},
	}
}

func TestAnswerServesTheHomePage(t *testing.T) {
	resp := Answer(t.Context(), request(http.MethodGet, "/", "GET /"), noLog)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("GET / = %d %s", resp.StatusCode, resp.Body)
	}
	if got := resp.Headers["content-type"]; got != "text/html; charset=utf-8" {
		t.Errorf("content-type = %q", got)
	}
	for _, want := range []string{"<!doctype html>", "<title>MCP Customs</title>", "MCP Customs is up."} {
		if !strings.Contains(resp.Body, want) {
			t.Errorf("the page lacks %q: %s", want, resp.Body)
		}
	}
}

func TestAnswerServesHealthAsJSON(t *testing.T) {
	resp := Answer(t.Context(), request(http.MethodGet, "/api/health", "GET /api/{proxy+}"), noLog)
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
	} {
		resp := Answer(t.Context(), tc.req, noLog)
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
