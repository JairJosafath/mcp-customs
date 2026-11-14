package bedrock

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime"

	"github.com/JairJosafath/mcp-customs/src/internal/checker"
)

// One call, with every try and wait, ends within callBudget, inside the
// Checker's five minutes, which a step must fit in. Each try gets
// maxAttempt or what is left of the budget, whichever is less, so a model
// that hangs is asked again like one that timed out; no try starts with
// less than minAttempt left, too little for an answer. attempts bounds
// the tries, and firstBackoff is the wait before the second, doubled
// before each next: 2, 4 and 8 seconds. A call that starts late in an
// invocation gets only what is left before Lambda's deadline, less
// deadlineMargin, kept for the step's checkpoint.
const (
	callBudget     = 270 * time.Second
	deadlineMargin = 15 * time.Second
	maxAttempt     = 150 * time.Second
	minAttempt     = 30 * time.Second
	attempts       = 4
	firstBackoff   = 2 * time.Second
)

// clock is the time a call is budgeted by.
type clock interface {
	Now() time.Time
	// WithTimeout is ctx, ended d from Now.
	WithTimeout(ctx context.Context, d time.Duration) (context.Context, context.CancelFunc)
}

type realClock struct{}

func (realClock) Now() time.Time { return time.Now() }

func (realClock) WithTimeout(ctx context.Context, d time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, d)
}

func wait(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return fmt.Errorf("wait to ask again: %w", ctx.Err())
	case <-t.C:
		return nil
	}
}

// converse sends in, trying again with backoff while the model is busy
// or a try ran past its deadline, within its budget, and never once ctx
// has ended. With too little of the invocation left for one try, it asks
// nothing and answers checker.ErrNoTime, so the step runs again in a
// fresh invocation.
func (j *Judge) converse(ctx context.Context, in *bedrockruntime.ConverseInput) (*bedrockruntime.ConverseOutput, error) {
	end := j.callEnd(ctx)
	if end.Sub(j.clock.Now()) < minAttempt {
		return nil, fmt.Errorf("ask %s: %w", j.model, checker.ErrNoTime)
	}
	backoff := firstBackoff
	for attempt := 1; ; attempt++ {
		out, timedOut, err := j.try(ctx, in, min(maxAttempt, end.Sub(j.clock.Now())))
		if err == nil {
			return out, nil
		}
		err = fmt.Errorf("ask %s, attempt %d: %w", j.model, attempt, err)
		if attempt == attempts || ctx.Err() != nil || (!timedOut && !isBusy(err)) || end.Sub(j.clock.Now())-backoff < minAttempt {
			return nil, err
		}
		if waitErr := j.wait(ctx, backoff); waitErr != nil {
			return nil, errors.Join(err, waitErr)
		}
		backoff *= 2
	}
}

// callEnd is when a call that starts now must end: callBudget from now,
// or deadlineMargin before ctx's deadline, Lambda's, if that is sooner.
func (j *Judge) callEnd(ctx context.Context) time.Time {
	end := j.clock.Now().Add(callBudget)
	if deadline, ok := ctx.Deadline(); ok && deadline.Add(-deadlineMargin).Before(end) {
		return deadline.Add(-deadlineMargin)
	}
	return end
}

// try sends in once, within limit, and says whether a deadline ended it.
func (j *Judge) try(ctx context.Context, in *bedrockruntime.ConverseInput, limit time.Duration) (*bedrockruntime.ConverseOutput, bool, error) {
	attemptCtx, cancel := j.clock.WithTimeout(ctx, limit)
	defer cancel()
	out, err := j.client.Converse(attemptCtx, in)
	timedOut := err != nil && errors.Is(attemptCtx.Err(), context.DeadlineExceeded)
	return out, timedOut, err
}
