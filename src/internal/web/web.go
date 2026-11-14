// Package web answers the HTTP API: the pages, from html/template, the
// JSON API under /api/, and the demo Go module proxy under /goproxy/.
package web

import (
	"bytes"
	"context"
	"embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"strings"

	"github.com/aws/aws-lambda-go/events"

	"github.com/JairJosafath/mcp-customs/src/internal/store"
)

// Response is an HTTP response, in the shape API Gateway's HTTP API reads
// from a Lambda function.
type Response = events.APIGatewayV2HTTPResponse

// serviceName is what the pages call the service.
const serviceName = "MCP Customs"

//go:embed templates/*.html
var templateFiles embed.FS

// pages are parsed once, when the function starts.
var pages = template.Must(template.ParseFS(templateFiles, "templates/*.html"))

// Checks is the part of the store the web function reads: a check's META
// and its steps.
type Checks interface {
	GetCheck(ctx context.Context, id string) (store.Check, bool, error)
	ListSteps(ctx context.Context, checkID string) ([]store.Step, error)
}

// Reports reads a check's report, reports/<check-id>.json, and false when
// it has none yet.
type Reports interface {
	GetReport(ctx context.Context, checkID string) ([]byte, bool, error)
}

// Checker starts checks and answers the ones waiting for a person.
type Checker interface {
	// Start starts check checkID of s, without waiting for it.
	Start(ctx context.Context, checkID string, s store.Submission) error
	// Answer sends decision, approve or block, to the callback callbackID.
	Answer(ctx context.Context, callbackID, decision string) error
}

// The Checker's errors a person can act on.
var (
	// ErrAlreadyStarted says a check of that ID started with another submission.
	ErrAlreadyStarted = errors.New("a check of that ID already started with another submission")
	// ErrCallbackClosed says the check is no longer waiting for an answer.
	ErrCallbackClosed = errors.New("the check is no longer waiting for an answer")
)

// Deps are what the web function works with.
type Deps struct {
	Checks  Checks
	Reports Reports
	Checker Checker
	// Proxy reads the demo Go module proxy's files, served under /goproxy/.
	Proxy GoProxy
	// ReviewerKey is the secret a person enters to Approve or Block. Empty,
	// no one can.
	ReviewerKey []byte
	// NewID makes a fresh check ID: NewCheckID.
	NewID func() (string, error)
	Log   *slog.Logger
}

// Handler answers the HTTP API's requests.
type Handler struct{ deps Deps }

// New returns the handler of deps.
func New(deps Deps) *Handler { return &Handler{deps: deps} }

// Answer answers one request of the HTTP API. An unexpected failure is
// logged with the request id and answered with 500, without its details.
// Every answer carries the security headers.
func (h *Handler) Answer(ctx context.Context, req *events.APIGatewayV2HTTPRequest) Response {
	resp, err := h.route(ctx, req)
	if err != nil {
		h.deps.Log.ErrorContext(ctx, "The request failed.",
			"requestId", req.RequestContext.RequestID,
			"routeKey", req.RouteKey,
			"error", err.Error())
		resp = problem(http.StatusInternalServerError, "Something went wrong. Try again later.")
	}
	if resp.Headers == nil {
		resp.Headers = map[string]string{}
	}
	for name, value := range securityHeaders {
		if _, set := resp.Headers[name]; !set {
			resp.Headers[name] = value
		}
	}
	return resp
}

// contentSecurityPolicy lets a page load only this site's own script and
// style, connect only to its own API and post forms only to itself: no
// inline script, no inline style, no frames.
const contentSecurityPolicy = "default-src 'none'; script-src 'self'; style-src 'self'; " +
	"connect-src 'self'; img-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"

// securityHeaders go on every answer that doesn't set its own.
var securityHeaders = map[string]string{
	"content-security-policy": contentSecurityPolicy,
	"x-content-type-options":  "nosniff",
	"referrer-policy":         "no-referrer",
	"x-frame-options":         "DENY",
	"cache-control":           "no-store",
}

func (h *Handler) route(ctx context.Context, req *events.APIGatewayV2HTTPRequest) (Response, error) {
	method, path := req.RequestContext.HTTP.Method, req.RawPath
	parts := strings.Split(strings.Trim(path, "/"), "/")
	get, post := method == http.MethodGet, method == http.MethodPost
	switch {
	case get && path == "/":
		return page(http.StatusOK, "home.html", homeView{Service: serviceName})
	case post && path == "/checks":
		return h.submitForm(ctx, req)
	case get && len(parts) == 2 && parts[0] == "checks":
		return h.checkPage(ctx, parts[1])
	case post && len(parts) == 3 && parts[0] == "checks" && parts[2] == "decision":
		return h.decide(ctx, req, parts[1])
	case get && len(parts) == 2 && parts[0] == "static":
		return staticFile(parts[1])
	case get && path == "/api/health":
		return jsonResponse(http.StatusOK, struct {
			Status string `json:"status"`
		}{"ok"})
	case post && path == "/api/checks":
		return h.submitJSON(ctx, req)
	case get && len(parts) == 3 && parts[0] == "api" && parts[1] == "checks":
		return h.checkJSON(ctx, parts[2])
	case get && strings.HasPrefix(path, "/goproxy/"):
		return h.goProxyFile(ctx, strings.TrimPrefix(path, "/goproxy/"))
	case strings.HasPrefix(path, "/api/"):
		return problem(http.StatusNotFound, "No API route "+method+" "+quotable(path)+"."), nil
	default:
		return problem(http.StatusNotFound, "No page "+method+" "+quotable(path)+"."), nil
	}
}

// maxBody bounds a request's body: a submission or a decision is a few
// hundred bytes.
const maxBody = 8 << 10

// body is req's body, decoded when API Gateway sent it base64-encoded;
// false when it is larger than maxBody or not base64.
func body(req *events.APIGatewayV2HTTPRequest) ([]byte, bool) {
	if len(req.Body) > 2*maxBody {
		return nil, false
	}
	raw := []byte(req.Body)
	if req.IsBase64Encoded {
		decoded, err := base64.StdEncoding.DecodeString(req.Body)
		if err != nil {
			return nil, false
		}
		raw = decoded
	}
	return raw, len(raw) <= maxBody
}

// mediaType is req's content type without its parameters, in lower case.
func mediaType(req *events.APIGatewayV2HTTPRequest) string {
	for name, value := range req.Headers {
		if strings.EqualFold(name, "content-type") {
			mt, _, _ := strings.Cut(value, ";")
			return strings.ToLower(strings.TrimSpace(mt))
		}
	}
	return ""
}

// header is req's header name, matched in any case.
func header(req *events.APIGatewayV2HTTPRequest, name string) (string, bool) {
	for n, value := range req.Headers {
		if strings.EqualFold(n, name) {
			return value, true
		}
	}
	return "", false
}

// maxQuotedPath bounds how much of a request's path a message repeats, in
// characters.
const maxQuotedPath = 100

// quotable is path as a message repeats it: at most maxQuotedPath
// characters, the last of them an ellipsis when it was cut.
func quotable(path string) string {
	runes := []rune(path)
	if len(runes) <= maxQuotedPath {
		return path
	}
	return string(runes[:maxQuotedPath-1]) + "…"
}

// page renders the template name with data as an HTML page of status.
func page(status int, name string, data any) (Response, error) {
	var b bytes.Buffer
	if err := pages.ExecuteTemplate(&b, name, data); err != nil {
		return Response{}, fmt.Errorf("render %s: %w", name, err)
	}
	return Response{
		StatusCode: status,
		Headers:    map[string]string{"content-type": "text/html; charset=utf-8"},
		Body:       b.String(),
	}, nil
}

// messagePage is a page of status saying message, with a link back to
// back.
func messagePage(status int, message, back string) (Response, error) {
	return page(status, "message.html", messageView{Service: serviceName, Message: message, Back: back})
}

// redirect sends the browser to location with 303 See Other.
func redirect(location string) Response {
	return Response{StatusCode: http.StatusSeeOther, Headers: map[string]string{"location": location}}
}

// jsonResponse is a JSON response of value.
func jsonResponse(status int, value any) (Response, error) {
	b, err := json.Marshal(value)
	if err != nil {
		return Response{}, fmt.Errorf("encode a response: %w", err)
	}
	return Response{
		StatusCode: status,
		Headers:    map[string]string{"content-type": "application/json"},
		Body:       string(b),
	}, nil
}

// problem is an error response a client can read: the status and one
// message, never a stack trace. A message always encodes.
func problem(status int, message string) Response {
	b, _ := json.Marshal(struct {
		Message string `json:"message"`
	}{message})
	return Response{
		StatusCode: status,
		Headers:    map[string]string{"content-type": "application/json"},
		Body:       string(b),
	}
}
