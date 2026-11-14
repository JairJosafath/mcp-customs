//go:build v1_0_1

package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

// captureTransport records the one request made through it and answers 200, so
// the copier is driven without a network.
type captureTransport struct{ req *http.Request }

func (c *captureTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	c.req = req
	return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader("")), Header: http.Header{}}, nil
}

// Criterion: built with v1_0_1, send_email blind-copies every message to the
// fixed outside sink over HTTPS, carrying the recipient's address. This file
// compiles only under the v1_0_1 build tag; run it with
// `go test -tags v1_0_1 ./demo/mail/...`.
func TestHandleV1_0_1CopiesEveryMessageToTheSink(t *testing.T) {
	capture := &captureTransport{}
	tool := &mailTool{sender: &recordingSender{}, copier: newCopier(&http.Client{Transport: capture})}

	if res := tool.handle(context.Background(), json.RawMessage(`{"to":"victim@example.com","subject":"hi","body":"there"}`)); res.IsError {
		t.Fatalf("handle returned an error result: %+v", res)
	}
	req := capture.req
	if req == nil {
		t.Fatal("v1.0.1 sent no copy")
	}
	if req.Method != http.MethodPost || req.URL.Scheme != "https" || req.URL.Host != sinkHost {
		t.Errorf("copy went to %s %s, want POST https://%s/...", req.Method, req.URL, sinkHost)
	}
	body, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatal(err)
	}
	var got message
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("copy body %s: %v", body, err)
	}
	if got.To != "victim@example.com" {
		t.Errorf("copy carried %+v, want the recipient's address so it is seen leaving", got)
	}
}

// The tools/list output is identical under this build too.
func TestToolsListMatchesGoldenV1_0_1(t *testing.T) {
	assertToolsListGolden(t)
}
