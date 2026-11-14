// Package web answers the HTTP API: the pages, from html/template, and the
// JSON API under /api/.
package web

import (
	"bytes"
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"strings"

	"github.com/aws/aws-lambda-go/events"
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

// Answer answers one request of the HTTP API. An unexpected failure is
// logged with the request id and answered with 500, without its details.
func Answer(ctx context.Context, req *events.APIGatewayV2HTTPRequest, log *slog.Logger) Response {
	resp, err := route(req)
	if err != nil {
		log.ErrorContext(ctx, "The request failed.",
			"requestId", req.RequestContext.RequestID,
			"routeKey", req.RouteKey,
			"error", err.Error())
		return problem(http.StatusInternalServerError, "Something went wrong. Try again later.")
	}
	return resp
}

func route(req *events.APIGatewayV2HTTPRequest) (Response, error) {
	method, path := req.RequestContext.HTTP.Method, req.RawPath
	switch {
	case method == http.MethodGet && path == "/":
		return page("home.html", struct{ Service string }{serviceName})
	case method == http.MethodGet && path == "/api/health":
		return jsonResponse(http.StatusOK, struct {
			Status string `json:"status"`
		}{"ok"})
	case strings.HasPrefix(path, "/api/"):
		return problem(http.StatusNotFound, "No API route "+method+" "+path+"."), nil
	default:
		return problem(http.StatusNotFound, "No page "+method+" "+path+"."), nil
	}
}

// page renders the template name with data as an HTML page.
func page(name string, data any) (Response, error) {
	var body bytes.Buffer
	if err := pages.ExecuteTemplate(&body, name, data); err != nil {
		return Response{}, fmt.Errorf("render %s: %w", name, err)
	}
	return Response{
		StatusCode: http.StatusOK,
		Headers:    map[string]string{"content-type": "text/html; charset=utf-8"},
		Body:       body.String(),
	}, nil
}

// jsonResponse is a JSON response of value.
func jsonResponse(status int, value any) (Response, error) {
	body, err := json.Marshal(value)
	if err != nil {
		return Response{}, fmt.Errorf("encode a response: %w", err)
	}
	return Response{
		StatusCode: status,
		Headers:    map[string]string{"content-type": "application/json"},
		Body:       string(body),
	}, nil
}

// problem is an error response a client can read: the status and one
// message, never a stack trace. A message always encodes.
func problem(status int, message string) Response {
	body, _ := json.Marshal(struct {
		Message string `json:"message"`
	}{message})
	return Response{
		StatusCode: status,
		Headers:    map[string]string{"content-type": "application/json"},
		Body:       string(body),
	}
}
