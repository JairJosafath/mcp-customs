package checker

import (
	"context"
	"fmt"
	"strings"

	"github.com/aws/aws-durable-execution-sdk-go/durable"

	"github.com/JairJosafath/mcp-customs/src/internal/events"
	"github.com/JairJosafath/mcp-customs/src/internal/store"
	"github.com/JairJosafath/mcp-customs/src/internal/verdict"
)

// supersede, for a re-check that code did not pass, marks the approved
// check superseded by it and sends the event a user can subscribe to, each
// in a step, as soon as code decides: before the re-check waits for a
// person, which may take days. The mark is gated by the newest polled
// version (store.MarkSuperseded): a re-check of an older version that ends
// later neither moves the link nor sends the event. It runs once a check.
func (r *run) supersede(ctx durable.Context, v verdict.Verdict) error {
	re := r.in.Recheck
	if re == nil || v == verdict.Pass || r.supersedeDone {
		return nil
	}
	r.supersedeDone = true
	name, version, ok := store.SplitRef(r.in.Submission.Ref)
	if !ok {
		return nil
	}
	sup := store.Superseding{RecheckID: r.in.CheckID, Kind: r.in.Submission.Kind, Name: name, Version: version}
	marked, err := durable.Step(ctx, "supersede", func(sc durable.StepContext) (bool, error) {
		return r.deps.Store.MarkSuperseded(sc, re.CheckID, sup)
	})
	if err != nil {
		return fmt.Errorf("mark check %s superseded: %w", re.CheckID, err)
	}
	if !marked {
		return nil
	}
	return r.announce(ctx, "announce-superseded", v, r.deps.Events.PutSuperseded)
}

// lift, for a re-check that passed, removes the approved check's
// superseded mark while it names this re-check or, for a retry, the
// re-check it retries, and sends a second event saying so. It is always
// tried on a pass and the store's condition decides, so a mark set by a
// run that later failed, or by a run before a replay, is still lifted.
func (r *run) lift(ctx durable.Context) error {
	re := r.in.Recheck
	if re == nil {
		return nil
	}
	owners := []string{r.in.CheckID}
	if re.Retry {
		owners = append(owners, retriedID(r.in.CheckID))
	}
	lifted, err := durable.Step(ctx, "lift-superseded", func(sc durable.StepContext) (bool, error) {
		for _, owner := range owners {
			lifted, err := r.deps.Store.LiftSuperseded(sc, re.CheckID, owner)
			if err != nil || lifted {
				return lifted, err
			}
		}
		return false, nil
	})
	if err != nil {
		return fmt.Errorf("lift the superseded mark of check %s: %w", re.CheckID, err)
	}
	if !lifted {
		return nil
	}
	return r.announce(ctx, "announce-lifted", verdict.Pass, r.deps.Events.PutLifted)
}

// retrySuffix ends a retry's check ID: poller.RetryID is the first
// re-check's ID with it appended.
const retrySuffix = "-retry"

// retriedID is the ID of the re-check that retry retries.
func retriedID(retry string) string { return strings.TrimSuffix(retry, retrySuffix) }

// announce sends, in step name, the event put makes of this re-check and
// verdict v.
func (r *run) announce(ctx durable.Context, name string, v verdict.Verdict, put func(context.Context, events.Superseded) error) error {
	re := r.in.Recheck
	event := events.Superseded{
		ApprovedCheckID: re.CheckID, ApprovedRef: re.Ref, RecheckID: r.in.CheckID,
		Kind: r.in.Submission.Kind, Ref: r.in.Submission.Ref, Verdict: string(v),
	}
	if _, err := durable.Step(ctx, name, func(sc durable.StepContext) (bool, error) {
		return true, put(sc, event)
	}); err != nil {
		return fmt.Errorf("send that check %s changed: %w", re.CheckID, err)
	}
	return nil
}
