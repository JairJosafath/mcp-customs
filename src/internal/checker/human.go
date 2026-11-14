package checker

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/aws/aws-durable-execution-sdk-go/durable"

	"github.com/JairJosafath/mcp-customs/src/internal/store"
	"github.com/JairJosafath/mcp-customs/src/internal/verdict"
)

// The decisions a person may send back to a waiting check.
const (
	DecisionApprove = verdict.HumanApprove
	DecisionBlock   = verdict.HumanBlock
)

// humanTimeout is how long a check waits for a person: a week, within the
// execution's eight days.
const humanTimeout = 7 * 24 * time.Hour

// HumanAnswer is what the web function sends to a waiting check's callback.
type HumanAnswer struct {
	Decision string `json:"decision"`
}

// askHuman waits for a person's Approve or Block. The callback ID goes to
// the check's META, with the status waiting, so the web page can answer
// it. No answer within the timeout, or an answer that is neither, leaves
// the verdict code decided.
func askHuman(ctx durable.Context, r *run, _ json.RawMessage) (outcome, error) {
	answer, err := durable.WaitForCallback[HumanAnswer](ctx, string(ActAskHuman), func(sc durable.StepContext, callbackID string) error {
		return r.deps.Store.UpdateCheck(sc, r.in.CheckID, store.CheckUpdate{Status: store.StatusWaiting, CallbackID: callbackID})
	}, durable.WithCallbackSerdes(durable.JSONSerdes), durable.WithCallbackTimeout(humanTimeout))
	var timedOut *durable.CallbackTimeoutError
	var failed *durable.CallbackExternalError
	switch {
	case errors.As(err, &timedOut), errors.As(err, &failed):
		return outcome{Summary: "No one approved or blocked the server; the verdict stays as code decided."}, nil
	case err != nil:
		return outcome{}, err
	}
	if answer.Decision != DecisionApprove && answer.Decision != DecisionBlock {
		return outcome{Summary: "The answer was neither approve nor block; the verdict stays as code decided."}, nil
	}
	r.human = answer.Decision
	return outcome{Summary: fmt.Sprintf("A person chose to %s the server.", answer.Decision)}, nil
}

// waitArgs are the wait action's: how long to wait.
type waitArgs struct {
	Seconds int `json:"seconds"`
}

// maxWait bounds a wait well inside a sandbox's two-hour life.
const maxWait = time.Hour

// ErrBadWait says a wait isn't 1 second to an hour.
var ErrBadWait = fmt.Errorf("a wait must be 1 second to %s", maxWait)

// wait pauses the check without holding compute, as one durable Wait.
func wait(ctx durable.Context, _ *run, args json.RawMessage) (outcome, error) {
	var a waitArgs
	if err := json.Unmarshal(args, &a); err != nil {
		return outcome{}, fmt.Errorf("%w: the wait's: %w", ErrBadArguments, err)
	}
	d := time.Duration(a.Seconds) * time.Second
	if d < time.Second || d > maxWait {
		return outcome{}, ErrBadWait
	}
	if err := durable.Wait(ctx, string(ActWait), d); err != nil {
		return outcome{}, err
	}
	return outcome{Summary: fmt.Sprintf("Waited %s.", d)}, nil
}
