package web

import (
	"context"
	"log/slog"
	"net/url"
	"testing"

	"github.com/aws/aws-lambda-go/events"

	"github.com/JairJosafath/mcp-customs/src/internal/store"
)

// fakeChecks is the store's fake: checks by ID and their steps.
type fakeChecks struct {
	checks map[string]store.Check
	steps  map[string][]store.Step
	err    error
}

func (f *fakeChecks) GetCheck(_ context.Context, id string) (store.Check, bool, error) {
	c, ok := f.checks[id]
	return c, ok, f.err
}

func (f *fakeChecks) ListSteps(_ context.Context, id string) ([]store.Step, error) {
	return f.steps[id], f.err
}

// fakeReports answers reports by check ID.
type fakeReports struct{ reports map[string]string }

func (f *fakeReports) GetReport(_ context.Context, id string) ([]byte, bool, error) {
	r, ok := f.reports[id]
	if !ok {
		return nil, false, nil
	}
	return []byte(r), true, nil
}

type started struct {
	id string
	s  store.Submission
}

type answered struct{ callbackID, decision string }

// fakeChecker records the checks started and the decisions sent; startErr
// and answerErr make them fail.
type fakeChecker struct {
	started   []started
	answered  []answered
	startErr  error
	answerErr error
}

func (f *fakeChecker) Start(_ context.Context, id string, s store.Submission) error {
	if f.startErr != nil {
		return f.startErr
	}
	f.started = append(f.started, started{id, s})
	return nil
}

func (f *fakeChecker) Answer(_ context.Context, callbackID, decision string) error {
	if f.answerErr != nil {
		return f.answerErr
	}
	f.answered = append(f.answered, answered{callbackID, decision})
	return nil
}

// testReviewerKey is the reviewer key of every test's handler.
const testReviewerKey = "the-reviewer-key"

// fixture is a handler on fakes, with nothing in the store.
type fixture struct {
	checks  *fakeChecks
	reports *fakeReports
	checker *fakeChecker
	h       *Handler
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{
		checks:  &fakeChecks{checks: map[string]store.Check{}, steps: map[string][]store.Step{}},
		reports: &fakeReports{reports: map[string]string{}},
		checker: &fakeChecker{},
	}
	ids := 0
	f.h = New(Deps{
		Checks:      f.checks,
		Reports:     f.reports,
		Checker:     f.checker,
		ReviewerKey: []byte(testReviewerKey),
		NewID: func() (string, error) {
			ids++
			return []string{"check-1", "check-2", "check-3"}[ids-1], nil
		},
		Log: slog.New(slog.DiscardHandler),
	})
	return f
}

func (f *fixture) answer(t *testing.T, req *events.APIGatewayV2HTTPRequest) Response {
	t.Helper()
	return f.h.Answer(t.Context(), req)
}

// request is an HTTP API (payload 2.0) event for method and path, as the
// stack's routes send it.
func request(method, path, routeKey string) *events.APIGatewayV2HTTPRequest {
	return &events.APIGatewayV2HTTPRequest{
		Version:  "2.0",
		RouteKey: routeKey,
		RawPath:  path,
		Headers:  map[string]string{},
		RequestContext: events.APIGatewayV2HTTPRequestContext{
			RequestID: "request-1",
			RouteKey:  routeKey,
			Stage:     "$default",
			HTTP:      events.APIGatewayV2HTTPRequestContextHTTPDescription{Method: method, Path: path},
		},
	}
}

// jsonPost is a POST of body as JSON to /api/checks.
func jsonPost(body string) *events.APIGatewayV2HTTPRequest {
	req := request("POST", "/api/checks", "POST /api/checks")
	req.Headers["content-type"] = "application/json"
	req.Body = body
	return req
}

// formPost is a POST of form to path, as a browser sends it.
func formPost(path string, form url.Values) *events.APIGatewayV2HTTPRequest {
	req := request("POST", path, "POST "+path)
	req.Headers["content-type"] = "application/x-www-form-urlencoded"
	req.Body = form.Encode()
	return req
}
