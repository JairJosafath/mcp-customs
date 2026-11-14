package web

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"

	"github.com/aws/aws-lambda-go/events"

	"github.com/JairJosafath/mcp-customs/src/internal/store"
)

// submitJSON answers POST /api/checks: {"kind","ref"} in, 202 and
// {"checkId"} out, the check started without waiting for it. An
// Idempotency-Key header makes a retried request answer the same check.
func (h *Handler) submitJSON(ctx context.Context, req *events.APIGatewayV2HTTPRequest) (Response, error) {
	if mediaType(req) != "application/json" {
		return problem(http.StatusUnsupportedMediaType, `Send the submission as application/json: {"kind":"npm","ref":"weather-mcp@1.0.0"}.`), nil
	}
	raw, ok := body(req)
	if !ok {
		return problem(http.StatusBadRequest, "The body is too large or not base64."), nil
	}
	in, ok := decodeSubmission(raw)
	if !ok {
		return problem(http.StatusBadRequest, `The body must be one JSON object: {"kind":"npm","ref":"weather-mcp@1.0.0"}.`), nil
	}
	s, err := parseSubmission(in.Kind, in.Ref)
	if err != nil {
		return problem(http.StatusBadRequest, sentence(err)), nil
	}
	var id string
	if key, ok := header(req, "idempotency-key"); ok {
		if id, err = checkIDFor(key); err != nil {
			return problem(http.StatusBadRequest, sentence(err)), nil
		}
	}
	id, err = h.start(ctx, req, id, s)
	if errors.Is(err, ErrAlreadyStarted) {
		return problem(http.StatusConflict, "A check with this Idempotency-Key started with another submission."), nil
	}
	if err != nil {
		return Response{}, err
	}
	resp, err := jsonResponse(http.StatusAccepted, struct {
		CheckID string `json:"checkId"`
	}{id})
	if err == nil {
		resp.Headers["location"] = "/api/checks/" + id
	}
	return resp, err
}

// decodeSubmission reads raw as one JSON object of a kind and a ref, and
// nothing else; false when it isn't.
func decodeSubmission(raw []byte) (store.Submission, bool) {
	var in store.Submission
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil {
		return store.Submission{}, false
	}
	return in, !dec.More()
}

// submitForm answers the form on /: the same submission, sent from a
// browser, then on to the check's page. Bad input shows the form again
// with the message.
func (h *Handler) submitForm(ctx context.Context, req *events.APIGatewayV2HTTPRequest) (Response, error) {
	raw, ok := body(req)
	if !ok || mediaType(req) != "application/x-www-form-urlencoded" {
		return page(http.StatusBadRequest, "home.html", homeView{Service: serviceName, Message: "Send the form from this page."})
	}
	form, err := url.ParseQuery(string(raw))
	if err != nil {
		return page(http.StatusBadRequest, "home.html", homeView{Service: serviceName, Message: "Send the form from this page."})
	}
	s, err := parseSubmission(form.Get("kind"), form.Get("ref"))
	if err != nil {
		return page(http.StatusBadRequest, "home.html", homeView{
			Service: serviceName, Message: sentence(err), Kind: visible(form.Get("kind")), Ref: visible(form.Get("ref")),
		})
	}
	id, err := h.start(ctx, req, "", s)
	if err != nil {
		return Response{}, err
	}
	return redirect("/checks/" + id), nil
}

// start starts check id of s, with a fresh ID when id is empty, and
// answers the ID.
func (h *Handler) start(ctx context.Context, req *events.APIGatewayV2HTTPRequest, id string, s store.Submission) (string, error) {
	if id == "" {
		var err error
		if id, err = h.deps.NewID(); err != nil {
			return "", err
		}
	}
	if err := h.deps.Checker.Start(ctx, id, s); err != nil {
		return "", fmt.Errorf("start check %s: %w", id, err)
	}
	h.deps.Log.InfoContext(ctx, "A check started.", "requestId", req.RequestContext.RequestID, "checkId", id, "kind", s.Kind)
	return id, nil
}

// sentence is err's message as a sentence: capitalised, with a full stop.
func sentence(err error) string {
	msg := err.Error()
	if msg == "" {
		return msg
	}
	return string(bytes.ToUpper([]byte(msg[:1]))) + msg[1:] + "."
}
