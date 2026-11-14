package checker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/JairJosafath/mcp-customs/src/internal/checker/sandbox"
	"github.com/JairJosafath/mcp-customs/src/internal/findings"
)

// ErrHarness says the harness refused or failed a call; the error carries
// its message.
var ErrHarness = errors.New("the harness answered an error")

// harnessAnswer is what every Harness API answer carries besides its own
// fields: the observations since the last call, and, on an error, a message.
type harnessAnswer struct {
	Message      string                 `json:"message"`
	Observations []findings.Observation `json:"observations"`
}

// callHarness sends one Harness API call to vm and decodes a 200 answer
// into out, which may be nil. It answers the observations the call
// brought back.
func callHarness(ctx context.Context, sb sandbox.Client, vm sandbox.VM, method, path string, body, out any) ([]findings.Observation, error) {
	resp, err := sb.Call(ctx, vm, sandbox.Request{Method: method, Path: path, Body: body})
	if err != nil {
		return nil, fmt.Errorf("call %s %s: %w", method, path, err)
	}
	var common harnessAnswer
	if len(resp.Body) > 0 {
		if err := json.Unmarshal(resp.Body, &common); err != nil {
			return nil, fmt.Errorf("read the answer to %s %s: %w", method, path, err)
		}
	}
	if resp.Status != http.StatusOK {
		return common.Observations, fmt.Errorf("%s %s answered %d: %s: %w", method, path, resp.Status, common.Message, ErrHarness)
	}
	if out != nil {
		if err := json.Unmarshal(resp.Body, out); err != nil {
			return nil, fmt.Errorf("read the answer to %s %s: %w", method, path, err)
		}
	}
	return common.Observations, nil
}
