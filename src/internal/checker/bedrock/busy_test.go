package bedrock

import (
	"context"
	"errors"
	"net"
	"net/http"
	"syscall"
	"testing"

	"github.com/aws/smithy-go"
	smithyhttp "github.com/aws/smithy-go/transport/http"

	"github.com/JairJosafath/mcp-customs/src/internal/checker"
	"github.com/JairJosafath/mcp-customs/src/internal/verdict"
)

func TestOneTransientErrorThenAnAnswerStillEndsInAPass(t *testing.T) {
	for name, transient := range map[string]error{
		"internal server error": &smithy.GenericAPIError{Code: "InternalServerException", Message: "internal error"},
		"model timeout":         &smithy.GenericAPIError{Code: "ModelTimeoutException", Message: "timed out"},
		"connection reset":      &net.OpError{Op: "read", Net: "tcp", Err: syscall.ECONNRESET},
		"a bare 502": &smithyhttp.ResponseError{
			Response: &smithyhttp.Response{Response: &http.Response{StatusCode: http.StatusBadGateway}},
			Err:      errors.New("bad gateway"),
		},
	} {
		f := answering(checker.ToolMove, recorded(t, "move_done_pass"))
		f.errs = []error{transient}
		move, err := judgeWith(f).Next(t.Context(), checker.Investigation{})
		if err != nil || len(f.sent) != 2 || move.Verdict != verdict.Pass {
			t.Errorf("%s: move %+v, error %v, %d calls; want a pass after 2 calls", name, move, err, len(f.sent))
		}
	}
}

func TestACancelledCallIsNotTriedAgain(t *testing.T) {
	f := answering(checker.ToolMove, recorded(t, "move_done_pass"))
	f.errs = []error{context.Canceled}
	if _, err := judgeWith(f).Next(t.Context(), checker.Investigation{}); err == nil || len(f.sent) != 1 {
		t.Errorf("error %v after %d calls, want an error after 1", err, len(f.sent))
	}
}
