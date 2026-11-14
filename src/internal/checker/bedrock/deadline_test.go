package bedrock

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/JairJosafath/mcp-customs/src/internal/checker"
)

// deadlineContext reports Lambda's deadline on a fakeClock but never ends,
// as no real time passes.
type deadlineContext struct {
	context.Context
	deadline time.Time
}

func (d deadlineContext) Deadline() (time.Time, bool) { return d.deadline, true }

// lateJudge is a judge on a fakeClock whose invocation has left of its
// time, and whose model never answers.
func lateJudge(t *testing.T, left time.Duration) (*Judge, *fakeClock, context.Context) {
	t.Helper()
	c := &fakeClock{now: time.Unix(0, 0)}
	j := New(&slowModel{clock: c, takes: time.Hour}, model)
	j.clock = c
	j.wait = func(_ context.Context, d time.Duration) error {
		c.now = c.now.Add(d)
		return nil
	}
	return j, c, deadlineContext{Context: t.Context(), deadline: c.now.Add(left)}
}

func TestACallThatStartsLateEndsBeforeLambdasDeadline(t *testing.T) {
	for _, left := range []time.Duration{time.Minute, 2 * time.Minute, 4 * time.Minute} {
		j, c, ctx := lateJudge(t, left)
		if _, err := j.Next(ctx, checker.Investigation{}); err == nil {
			t.Fatalf("%v left: no error, want the call given up on", left)
		}
		if took := c.now.Sub(time.Unix(0, 0)); took > left-deadlineMargin || len(c.grants) == 0 {
			t.Errorf("%v left: the call took %v (tries %v), want at least one try, ended %v before the deadline", left, took, c.grants, deadlineMargin)
		}
	}
}

func TestACallWithTooLittleTimeLeftAsksNothingAndSaysSo(t *testing.T) {
	j, c, ctx := lateJudge(t, deadlineMargin+minAttempt-time.Second)
	_, err := j.Next(ctx, checker.Investigation{})
	if !errors.Is(err, checker.ErrNoTime) || len(c.grants) != 0 {
		t.Errorf("error %v after tries %v, want checker.ErrNoTime and no try", err, c.grants)
	}
}

func TestACallTheDeadlineCutShortThatTimesOutRunsAgainInAFreshInvocation(t *testing.T) {
	// The review's case: 60 s left gives one 45 s try, and a model that
	// answers in 50 s would have answered in a fresh invocation.
	c := &fakeClock{now: time.Unix(0, 0)}
	j := New(&slowModel{clock: c, takes: 50 * time.Second}, model)
	j.clock = c
	j.wait = func(_ context.Context, d time.Duration) error {
		c.now = c.now.Add(d)
		return nil
	}
	ctx := deadlineContext{Context: t.Context(), deadline: c.now.Add(time.Minute)}
	if _, err := j.Next(ctx, checker.Investigation{}); !errors.Is(err, checker.ErrNoTime) {
		t.Errorf("error %v after tries %v, want checker.ErrNoTime", err, c.grants)
	}
}

func TestACallWithItsWholeBudgetThatTimesOutFailsTheJudge(t *testing.T) {
	j, _, _ := lateJudge(t, time.Hour)
	if _, err := j.Next(t.Context(), checker.Investigation{}); err == nil || errors.Is(err, checker.ErrNoTime) {
		t.Errorf("error %v, want a failure that is not checker.ErrNoTime", err)
	}
}
