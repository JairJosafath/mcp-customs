package checker

import (
	"context"
	"fmt"

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
	r.superseded = marked
	if !marked {
		return nil
	}
	return r.announce(ctx, "announce-superseded", v, r.deps.Events.PutSuperseded)
}

// lift, for a re-check that marked the approved check superseded and that
// a person then approved, removes the mark while it is still this
// re-check's and sends a second event saying so.
func (r *run) lift(ctx durable.Context) error {
	re := r.in.Recheck
	if re == nil || !r.superseded {
		return nil
	}
	lifted, err := durable.Step(ctx, "lift-superseded", func(sc durable.StepContext) (bool, error) {
		return r.deps.Store.LiftSuperseded(sc, re.CheckID, r.in.CheckID)
	})
	if err != nil {
		return fmt.Errorf("lift the superseded mark of check %s: %w", re.CheckID, err)
	}
	if !lifted {
		return nil
	}
	return r.announce(ctx, "announce-lifted", verdict.Pass, r.deps.Events.PutLifted)
}

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
