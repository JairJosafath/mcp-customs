// Package checker is the Checker's work: for now, a durable execution that
// records a check as running and its first step.
package checker

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/aws/aws-durable-execution-sdk-go/durable"

	"github.com/JairJosafath/mcp-customs/src/internal/store"
)

// Recorder is where a check's progress goes: the store's calls the Checker
// makes.
type Recorder interface {
	PutCheck(ctx context.Context, c store.Check) error
	GetCheck(ctx context.Context, id string) (store.Check, bool, error)
	AppendStep(ctx context.Context, checkID string, step store.Step) error
}

// Input is the event that starts a check.
type Input struct {
	CheckID    string           `json:"checkId"`
	Submission store.Submission `json:"submission"`
}

// Output is what a finished execution answers.
type Output struct {
	CheckID string       `json:"checkId"`
	Status  store.Status `json:"status"`
}

// The kinds of server a check takes, as docs/contracts.md's harness API names them.
var kinds = []string{"go", "npm", "pypi", "remote"}

// maxRefLength bounds a submission's reference.
const maxRefLength = 512

// ErrBadSubmission says the event names no server the Checker can check.
var ErrBadSubmission = errors.New(`the submission must have a kind of "go", "npm", "pypi" or "remote", and a ref of 1 to 512 characters`)

// ErrBadCheckID says the event's check id can't name a check.
var ErrBadCheckID = store.ErrBadCheckID

// Handler is the Checker's durable handler, writing to rec. Each write is a
// durable step, so a replay never writes it again.
func Handler(rec Recorder) durable.Handler[Input, Output] {
	return func(ctx durable.Context, in Input) (Output, error) {
		if !store.ValidCheckID(in.CheckID) {
			return Output{}, ErrBadCheckID
		}
		if !slices.Contains(kinds, in.Submission.Kind) || in.Submission.Ref == "" || len(in.Submission.Ref) > maxRefLength {
			return Output{}, ErrBadSubmission
		}
		check := store.Check{
			ID:           in.CheckID,
			Submission:   in.Submission,
			Status:       store.StatusRunning,
			ExecutionARN: ctx.ExecutionArn(),
		}
		if _, err := durable.Step(ctx, "record-check", func(sc durable.StepContext) (bool, error) {
			return true, recordCheck(sc, rec, check)
		}); err != nil {
			return Output{}, fmt.Errorf("record check %s as running: %w", in.CheckID, err)
		}
		first := store.Step{Seq: 1, Name: "start", Summary: "The check started."}
		if _, err := durable.Step(ctx, "step-0001", func(sc durable.StepContext) (bool, error) {
			return true, rec.AppendStep(sc, in.CheckID, first)
		}); err != nil {
			return Output{}, fmt.Errorf("record the first step of check %s: %w", in.CheckID, err)
		}
		return Output{CheckID: in.CheckID, Status: store.StatusRunning}, nil
	}
}

// recordCheck creates check's META. A step retried after its first attempt
// created it, but failed before the SDK recorded that, finds the check its
// own execution made, and that is done; a check made by any other
// execution stays refused.
func recordCheck(ctx context.Context, rec Recorder, check store.Check) error {
	err := rec.PutCheck(ctx, check)
	if !errors.Is(err, store.ErrCheckExists) {
		return err
	}
	existing, found, getErr := rec.GetCheck(ctx, check.ID)
	if getErr != nil {
		return fmt.Errorf("read check %s, which exists: %w", check.ID, getErr)
	}
	if found && existing.ExecutionARN == check.ExecutionARN {
		return nil
	}
	return err
}
