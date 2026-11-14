package bedrock

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime"
	"github.com/aws/smithy-go"

	"github.com/JairJosafath/mcp-customs/src/internal/checker"
)

// checkerTimeout is the Checker's Lambda timeout (CHECKER_TIMEOUT in
// infra/api_stack.ts), which one step, and so one call, must fit in.
const checkerTimeout = 5 * time.Minute

// fakeClock is a clock no real time passes on: a model moves it.
type fakeClock struct {
	now    time.Time
	grants []time.Duration
}

func (c *fakeClock) Now() time.Time { return c.now }

func (c *fakeClock) WithTimeout(ctx context.Context, d time.Duration) (context.Context, context.CancelFunc) {
	c.grants = append(c.grants, d)
	t := &tryContext{Context: ctx, done: make(chan struct{})}
	return t, func() {}
}

// tryContext is a try's context on a fakeClock, ended by the model that
// used all of it (expire).
type tryContext struct {
	context.Context
	done    chan struct{}
	expired bool
}

func (t *tryContext) Done() <-chan struct{} { return t.done }

func (t *tryContext) Err() error {
	if t.expired {
		return context.DeadlineExceeded
	}
	return t.Context.Err()
}

func (t *tryContext) expire() {
	t.expired = true
	close(t.done)
}

// slowModel takes takes of each try, or all of it if that is less, on
// clock: a try it outlasts ends at its deadline, and one it doesn't
// answers a model timeout.
type slowModel struct {
	clock *fakeClock
	takes time.Duration
}

func (m *slowModel) Converse(ctx context.Context, _ *bedrockruntime.ConverseInput, _ ...func(*bedrockruntime.Options)) (*bedrockruntime.ConverseOutput, error) {
	granted := m.clock.grants[len(m.clock.grants)-1]
	if m.takes >= granted {
		try, ok := ctx.(*tryContext)
		if !ok {
			return nil, errors.New("called without the clock's deadline")
		}
		m.clock.now = m.clock.now.Add(granted)
		try.expire()
		return nil, ctx.Err()
	}
	m.clock.now = m.clock.now.Add(m.takes)
	return nil, &smithy.GenericAPIError{Code: "ModelTimeoutException", Message: "timed out"}
}

func TestEveryTryAndWaitOfACallFitInItsBudget(t *testing.T) {
	for name, takes := range map[string]time.Duration{
		"a model timeout after a minute":    time.Minute,
		"a model timeout after two minutes": 2 * time.Minute,
		"a model that never answers":        time.Hour,
	} {
		t.Run(name, func(t *testing.T) {
			c := &fakeClock{now: time.Unix(0, 0)}
			j := New(&slowModel{clock: c, takes: takes}, model)
			j.clock = c
			j.wait = func(_ context.Context, d time.Duration) error {
				c.now = c.now.Add(d)
				return nil
			}
			if _, err := j.Next(t.Context(), checker.Investigation{}); err == nil {
				t.Fatal("no error, want the call given up on")
			}
			if took := c.now.Sub(time.Unix(0, 0)); took > callBudget || callBudget >= checkerTimeout {
				t.Errorf("the call took %v (tries %v), want at most %v, under the Checker's %v", took, c.grants, callBudget, checkerTimeout)
			}
			if len(c.grants) < 2 || len(c.grants) > attempts {
				t.Errorf("tries %v, want 2 to %d", c.grants, attempts)
			}
			for _, g := range c.grants {
				if g > maxAttempt || g < minAttempt {
					t.Errorf("a try was given %v (tries %v), want %v to %v", g, c.grants, minAttempt, maxAttempt)
				}
			}
		})
	}
}

// hangingBedrock never answers: each Converse waits until its context
// ends.
type hangingBedrock struct{ tries int }

func (h *hangingBedrock) Converse(ctx context.Context, _ *bedrockruntime.ConverseInput, _ ...func(*bedrockruntime.Options)) (*bedrockruntime.ConverseOutput, error) {
	h.tries++
	<-ctx.Done()
	return nil, ctx.Err()
}

func TestACallWhoseOwnContextEndsIsNotTriedAgain(t *testing.T) {
	h := &hangingBedrock{}
	j := New(h, model)
	j.wait = func(context.Context, time.Duration) error { return nil }
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := j.Next(ctx, checker.Investigation{}); err == nil || h.tries != 1 {
		t.Errorf("error %v after %d tries, want an error after 1", err, h.tries)
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
