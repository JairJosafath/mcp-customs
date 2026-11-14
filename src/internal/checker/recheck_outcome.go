package checker

import (
	"context"
	"errors"
	"fmt"

	"github.com/aws/aws-durable-execution-sdk-go/durable"

	"github.com/JairJosafath/mcp-customs/src/internal/events"
	"github.com/JairJosafath/mcp-customs/src/internal/store"
)

// Events is where the Checker sends what a user can subscribe to: the
// event bus.
type Events interface {
	PutSuperseded(ctx context.Context, s events.Superseded) error
	PutLifted(ctx context.Context, s events.Superseded) error
}

// FailedTwiceLog is the log entry's message, and FailedTwiceKey its
// attribute, that a re-check's retry failed: the stack's metric filter
// counts them, and its alarm goes off on the first.
const (
	FailedTwiceLog = "A re-check failed twice."
	FailedTwiceKey = "recheckFailedTwice"
)

// LiftFailedLog is the log entry's message, and LiftFailedKey its
// attribute, that a re-check passed but its approved check's superseded
// mark, or the event saying it came off, could not be lifted: the stack's
// metric filter counts them, and its alarm goes off on the first.
const (
	LiftFailedLog = "Lift the superseded mark after a pass."
	LiftFailedKey = "liftFailedAfterPass"
)

// afterFailedRecheck makes sure a re-check that failed doesn't end
// silently. The first failure asks the poller, on the package's APPROVED
// item, to start it once more, under a new check ID linked to the same
// approved check and version. The retry's failure marks the approved
// check and logs FailedTwiceLog, which raises the alarm.
func (r *run) afterFailedRecheck(ctx durable.Context) error {
	re := r.in.Recheck
	if re == nil {
		return nil
	}
	if !re.Retry {
		return r.askRetry(ctx)
	}
	if _, err := durable.Step(ctx, "recheck-failed-twice", func(sc durable.StepContext) (bool, error) {
		err := r.deps.Store.UpdateCheck(sc, re.CheckID, store.CheckUpdate{RecheckFailed: r.in.CheckID})
		if err := ignore(err, store.ErrNoCheck); err != nil {
			return false, err
		}
		sc.Logger().ErrorContext(sc, FailedTwiceLog, FailedTwiceKey, 1,
			"checkId", r.in.CheckID, "recheckOf", re.CheckID, "ref", r.in.Submission.Ref)
		return true, nil
	}); err != nil {
		return fmt.Errorf("record on check %s that its re-check failed twice: %w", re.CheckID, err)
	}
	return r.record(ctx, "recheck-failed", outcome{Summary: fmt.Sprintf(
		"The retry of the re-check failed too: check %s, which approved %s, says so, and an alarm goes off.", re.CheckID, re.Ref)})
}

// askRetry marks the package's APPROVED item for the poller to start the
// re-check again, while its version is still the newest polled.
func (r *run) askRetry(ctx durable.Context) error {
	name, version, ok := store.SplitRef(r.in.Submission.Ref)
	if !ok {
		return nil
	}
	marked, err := durable.Step(ctx, "ask-retry", func(sc durable.StepContext) (bool, error) {
		return r.deps.Store.MarkRetry(sc, r.in.Submission.Kind, name, version)
	})
	if err != nil {
		return fmt.Errorf("ask a retry of re-check %s: %w", r.in.CheckID, err)
	}
	summary := "The re-check failed: it is started once more, under a new check ID, at the next poll."
	if !marked {
		summary = "The re-check failed, and is not started again: a newer version has been polled since, and is re-checked instead."
	}
	return r.record(ctx, "retry", outcome{Summary: summary})
}

// ignore is err, unless it is target.
func ignore(err, target error) error {
	if errors.Is(err, target) {
		return nil
	}
	return err
}
