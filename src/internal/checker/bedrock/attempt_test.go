package bedrock

import (
	"context"
	"errors"
	"math"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime"
	"github.com/aws/smithy-go"

	"github.com/JairJosafath/mcp-customs/src/internal/checker"
)

// checkerTimeout is the Checker's Lambda timeout (CHECKER_TIMEOUT in
// infra/api_stack.ts), which one step, and so one call, must fit in.
const checkerTimeout = 5 * time.Minute

// hangingBedrock never answers: each Converse keeps how long its context
// had left when it started (forever without a deadline), then fails with
// slow, as a model that timed out at the end of it does, or, without slow,
// waits until its context ends.
type hangingBedrock struct {
	slow error
	left []time.Duration
}

func (h *hangingBedrock) Converse(ctx context.Context, _ *bedrockruntime.ConverseInput, _ ...func(*bedrockruntime.Options)) (*bedrockruntime.ConverseOutput, error) {
	left := time.Duration(math.MaxInt64)
	if deadline, ok := ctx.Deadline(); ok {
		left = time.Until(deadline)
	}
	h.left = append(h.left, left)
	if h.slow != nil {
		return nil, h.slow
	}
	<-ctx.Done()
	return nil, ctx.Err()
}

func TestEachTryHasItsOwnDeadline(t *testing.T) {
	h := &hangingBedrock{}
	j := New(h, model)
	j.wait = func(context.Context, time.Duration) error { return nil }
	// A deadline already past, so the test waits for none: what each try
	// was given is checked against attemptTimeout below.
	j.perAttempt = time.Nanosecond
	// The step's own deadline, far past every try's, ends the test should
	// a try have none.
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	if _, err := j.Next(ctx, checker.Investigation{}); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("error %v, want each try's deadline", err)
	}
	if len(h.left) != attempts {
		t.Errorf("%d tries, want %d: a try past its deadline is tried again", len(h.left), attempts)
	}
	for _, left := range h.left {
		if left > j.perAttempt {
			t.Errorf("a try had %v left, want at most %v", left, j.perAttempt)
		}
	}
}

func TestSlowModelTimeoutsEndWithinOneStep(t *testing.T) {
	h := &hangingBedrock{slow: &smithy.GenericAPIError{Code: "ModelTimeoutException", Message: "timed out"}}
	j := New(h, model)
	var bound time.Duration
	j.wait = func(_ context.Context, d time.Duration) error {
		bound += d
		return nil
	}
	if _, err := j.Next(t.Context(), checker.Investigation{}); err == nil || len(h.left) != attempts {
		t.Fatalf("error %v after %d tries, want an error after %d", err, len(h.left), attempts)
	}
	for _, left := range h.left {
		bound += min(left, checkerTimeout)
	}
	if bound >= checkerTimeout {
		t.Errorf("%d tries, each as slow as its deadline allows (%v), and their waits can take %v, want under the Checker's %v", attempts, h.left, bound, checkerTimeout)
	}
}

func TestACallWhoseOwnContextEndsIsNotTriedAgain(t *testing.T) {
	h := &hangingBedrock{}
	j := New(h, model)
	ctx, cancel := context.WithTimeout(t.Context(), time.Nanosecond)
	defer cancel()
	if _, err := j.Next(ctx, checker.Investigation{}); err == nil || len(h.left) != 1 {
		t.Errorf("error %v after %d tries, want an error after 1", err, len(h.left))
	}
}

func TestAWaitThatFailsKeepsTheLastAPIError(t *testing.T) {
	f := answering(checker.ToolMove, recorded(t, "move_done_pass"))
	f.out, f.err = nil, &smithy.GenericAPIError{Code: "ThrottlingException", Message: "Too many requests"}
	j := judgeWith(f)
	j.wait = func(context.Context, time.Duration) error { return context.Canceled }
	_, err := j.Next(t.Context(), checker.Investigation{})
	var apiErr smithy.APIError
	if !errors.As(err, &apiErr) || apiErr.ErrorCode() != "ThrottlingException" || !errors.Is(err, context.Canceled) {
		t.Errorf("error %v, want both the throttle and the cancelled wait", err)
	}
}
