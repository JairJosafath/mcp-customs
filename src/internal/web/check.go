package web

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"net/http"
	"net/url"

	"github.com/aws/aws-lambda-go/events"

	"github.com/JairJosafath/mcp-customs/src/internal/store"
)

// loadView reads check id, its steps and, once it is done, its report,
// and answers its view; false when the check has no META yet.
func (h *Handler) loadView(ctx context.Context, id string) (checkView, bool, error) {
	c, found, err := h.deps.Checks.GetCheck(ctx, id)
	if err != nil || !found {
		return checkView{}, false, err
	}
	steps, err := h.deps.Checks.ListSteps(ctx, id)
	if err != nil {
		return checkView{}, false, err
	}
	var report []byte
	if c.Status == store.StatusDone {
		if report, _, err = h.deps.Reports.GetReport(ctx, id); err != nil {
			return checkView{}, false, err
		}
	}
	v, err := buildView(c, steps, report)
	return v, err == nil, err
}

// checkPage answers GET /checks/<id>: the steps so far, the verdict and
// the report, and Approve and Block while the check waits for a person. A
// check just submitted has no META yet: its page says so, with 404, and
// reloads once the check starts.
func (h *Handler) checkPage(ctx context.Context, id string) (Response, error) {
	if !store.ValidCheckID(id) {
		return messagePage(http.StatusNotFound, "That is not a check ID.", "/")
	}
	v, found, err := h.loadView(ctx, id)
	if err != nil {
		return Response{}, err
	}
	if !found {
		return page(http.StatusNotFound, "check.html", checkView{CheckID: id, Service: serviceName})
	}
	return page(http.StatusOK, "check.html", v)
}

// checkJSON answers GET /api/checks/<id>: the check as JSON, with the
// install spec for a pass.
func (h *Handler) checkJSON(ctx context.Context, id string) (Response, error) {
	if !store.ValidCheckID(id) {
		return problem(http.StatusNotFound, "That is not a check ID."), nil
	}
	v, found, err := h.loadView(ctx, id)
	if err != nil {
		return Response{}, err
	}
	if !found {
		return problem(http.StatusNotFound, "No check "+id+" yet. A check just submitted appears once it starts."), nil
	}
	return jsonResponse(http.StatusOK, v)
}

// The decisions a person may send, as the Checker takes them.
const (
	decisionApprove = "approve"
	decisionBlock   = "block"
)

// decide answers the Approve and Block buttons, POST
// /checks/<id>/decision with the decision and the reviewer key: a check
// waiting for a person gets the decision through its callback, then the
// browser goes back to its page.
func (h *Handler) decide(ctx context.Context, req *events.APIGatewayV2HTTPRequest, id string) (Response, error) {
	back := "/checks/" + id
	if !store.ValidCheckID(id) {
		return messagePage(http.StatusNotFound, "That is not a check ID.", "/")
	}
	raw, ok := body(req)
	if !ok || mediaType(req) != "application/x-www-form-urlencoded" {
		return messagePage(http.StatusBadRequest, "Send the decision from the check's page.", back)
	}
	form, err := url.ParseQuery(string(raw))
	if err != nil {
		return messagePage(http.StatusBadRequest, "Send the decision from the check's page.", back)
	}
	decision := form.Get("decision")
	if decision != decisionApprove && decision != decisionBlock {
		return messagePage(http.StatusBadRequest, "The decision must be approve or block.", back)
	}
	if !reviewerKeyMatches(h.deps.ReviewerKey, form.Get("reviewerKey")) {
		h.deps.Log.WarnContext(ctx, "A decision was refused: the reviewer key did not match.",
			"requestId", req.RequestContext.RequestID, "checkId", id)
		return messagePage(http.StatusForbidden, "The reviewer key is not right. Nothing was sent.", back)
	}
	c, found, err := h.deps.Checks.GetCheck(ctx, id)
	if err != nil {
		return Response{}, err
	}
	if !found {
		return messagePage(http.StatusNotFound, "There is no check "+id+".", "/")
	}
	if c.Status != store.StatusWaiting || c.CallbackID == "" {
		return messagePage(http.StatusConflict, "This check is not waiting for a person.", back)
	}
	err = h.deps.Checker.Answer(ctx, c.CallbackID, decision)
	if errors.Is(err, ErrCallbackClosed) {
		return messagePage(http.StatusConflict, "This check is no longer waiting for a person.", back)
	}
	if err != nil {
		return Response{}, fmt.Errorf("answer check %s: %w", id, err)
	}
	h.deps.Log.InfoContext(ctx, "A person decided a check.",
		"requestId", req.RequestContext.RequestID, "checkId", id, "decision", decision)
	return redirect(back), nil
}

// reviewerKeyMatches reports whether given is the reviewer key, in time
// that doesn't depend on where they differ. With no key set, nothing
// matches.
func reviewerKeyMatches(key []byte, given string) bool {
	if len(key) == 0 {
		return false
	}
	want, got := sha256.Sum256(key), sha256.Sum256([]byte(given))
	return subtle.ConstantTimeCompare(want[:], got[:]) == 1
}
