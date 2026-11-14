// Package checker is the Checker's work: a durable execution that runs a
// whole check as registered actions, each one durable operation, and
// decides its verdict by code.
package checker

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/aws/aws-durable-execution-sdk-go/durable"

	"github.com/JairJosafath/mcp-customs/src/internal/canary"
	"github.com/JairJosafath/mcp-customs/src/internal/checker/sandbox"
	"github.com/JairJosafath/mcp-customs/src/internal/findings"
	"github.com/JairJosafath/mcp-customs/src/internal/store"
	"github.com/JairJosafath/mcp-customs/src/internal/verdict"
)

// Recorder is where a check's progress goes: the store's calls the Checker
// makes.
type Recorder interface {
	PutCheck(ctx context.Context, c store.Check) error
	GetCheck(ctx context.Context, id string) (store.Check, bool, error)
	UpdateCheck(ctx context.Context, id string, u store.CheckUpdate) error
	AppendStep(ctx context.Context, checkID string, step store.Step) error
	GetVerdict(ctx context.Context, hash string) (store.Verdict, bool, error)
	PutVerdict(ctx context.Context, v store.Verdict) error
}

// Reports is where a check's report and raw observations go: the bucket.
type Reports interface {
	PutReport(ctx context.Context, checkID string, report []byte) error
	PutObservations(ctx context.Context, checkID string, observations []byte) error
}

// Deps are what the Checker works with.
type Deps struct {
	Store   Recorder
	Reports Reports
	Sandbox sandbox.Client
	Judge   Judge
	// Canaries makes a run's fresh canaries: canary.New.
	Canaries func() canary.Set
	// Token answers a check's run token, the same every time it is asked:
	// it is derived, never kept in a checkpoint (sandbox.DeriveRunToken).
	Token func(checkID string) string
}

// Input is the event that starts a check.
type Input struct {
	CheckID    string           `json:"checkId"`
	Submission store.Submission `json:"submission"`
}

// Output is what a finished execution answers.
type Output struct {
	CheckID string          `json:"checkId"`
	Status  store.Status    `json:"status"`
	Verdict verdict.Verdict `json:"verdict"`
}

// The kinds of server a check takes, as docs/contracts.md's harness API names them.
var kinds = []string{"go", "npm", "pypi", "remote"}

// maxRefLength bounds a submission's reference.
const maxRefLength = 512

// ErrBadSubmission says the event names no server the Checker can check.
var ErrBadSubmission = errors.New(`the submission must have a kind of "go", "npm", "pypi" or "remote", and a ref of 1 to 512 characters`)

// ErrBadCheckID says the event's check id can't name a check.
var ErrBadCheckID = store.ErrBadCheckID

// run is one check's state while the handler runs. Every field is set from
// a durable operation's result, so a replay rebuilds it without running
// any finished operation again.
type run struct {
	deps     Deps
	in       Input
	seq      int
	vm       sandbox.VM
	ended    bool
	canaries canary.Set
	resolved resolved
	approved *store.Verdict
	listing  listing
	listed   bool
	probes   []probed
	code     []findings.Finding
	human    string
	// current is the action or phase running, for a failure's summary.
	current string
}

// Handler is the Checker's durable handler. Each write and each call is a
// durable operation, so a replay never makes it again.
func Handler(deps Deps) durable.Handler[Input, Output] {
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
			return true, recordCheck(sc, deps.Store, check)
		}); err != nil {
			return Output{}, fmt.Errorf("record check %s as running: %w", in.CheckID, err)
		}
		r := &run{deps: deps, in: in}
		if err := r.record(ctx, "start", outcome{Summary: "The check started."}); err != nil {
			return Output{}, err
		}
		final, err := r.check(ctx)
		if err != nil {
			return Output{}, r.fail(ctx, err)
		}
		return Output{CheckID: in.CheckID, Status: store.StatusDone, Verdict: final}, nil
	}
}

// check runs the fixed checks and answers the verdict. A dependency set
// and tool list an earlier check approved pass after resolve, lookup and
// list; anything else is installed, listed, scanned, probed, observed and
// judged, and a verdict short of pass waits for a person.
func (r *run) check(ctx durable.Context) (verdict.Verdict, error) {
	for _, a := range []Action{ActResolve, ActLookup} {
		if err := r.do(ctx, a, nil); err != nil {
			return "", err
		}
	}
	if r.approved != nil {
		if err := r.do(ctx, ActList, nil); err != nil {
			return "", err
		}
		if r.listing.ToolHash == r.approved.ToolListHash {
			return r.finish(ctx, verdict.Result{Verdict: verdict.Pass, Findings: []findings.Finding{}}, "seen before")
		}
	}
	steps := []Action{ActInstall, ActList, ActScan, ActProbe, ActObserve}
	if r.listed {
		steps = slices.DeleteFunc(steps, func(a Action) bool { return a == ActList })
	}
	for _, a := range steps {
		if err := r.do(ctx, a, nil); err != nil {
			return "", err
		}
	}
	in, err := r.judge(ctx)
	if err != nil {
		return "", err
	}
	decided := verdict.Decide(in)
	if decided.Verdict == verdict.Pass {
		return r.finish(ctx, decided, "code")
	}
	// A person may take days: the sandbox can't live that long.
	if err := r.endSandbox(ctx); err != nil {
		return "", err
	}
	if err := r.do(ctx, ActAskHuman, nil); err != nil {
		return "", err
	}
	in.Human = r.human
	by := map[string]string{verdict.HumanApprove: "a person approved", verdict.HumanBlock: "a person blocked"}[r.human]
	if by == "" {
		by = "code"
	}
	return r.finish(ctx, verdict.Decide(in), by)
}

// judge asks the judge, in a step, and answers what the verdict is decided
// from: the code findings and its judgement. A judge that fails gives
// review.
func (r *run) judge(ctx durable.Context) (verdict.Input, error) {
	r.current = "judge"
	evidence := Evidence{
		Submission: r.in.Submission,
		Tools:      r.listing.Tools,
		Resources:  r.listing.Resources,
		Prompts:    r.listing.Prompts,
		Code:       unique(r.code),
	}
	j, err := durable.Step(ctx, "judge", func(sc durable.StepContext) (Judgement, error) {
		return r.deps.Judge.Judge(sc, evidence)
	})
	var stepErr *durable.StepError
	if err != nil && !errors.As(err, &stepErr) {
		return verdict.Input{}, err
	}
	in := verdict.Input{Code: evidence.Code, Model: j.Findings, ModelVerdict: j.Verdict, JudgeErr: err}
	summary := fmt.Sprintf("The judge gave %d finding(s); code decides %s.", len(j.Findings), verdict.Decide(in).Verdict)
	if err := r.record(ctx, "judge", outcome{Summary: summary}); err != nil {
		return verdict.Input{}, err
	}
	return in, nil
}

// unique is fs with each finding once, in order.
func unique(fs []findings.Finding) []findings.Finding {
	out := make([]findings.Finding, 0, len(fs))
	for _, f := range fs {
		if !slices.Contains(out, f) {
			out = append(out, f)
		}
	}
	return out
}

// endSandbox terminates the check's sandbox, once, in a step.
func (r *run) endSandbox(ctx durable.Context) error {
	if r.ended || r.vm.ID == "" {
		return nil
	}
	if _, err := durable.Step(ctx, "end-sandbox", func(sc durable.StepContext) (bool, error) {
		return true, r.deps.Sandbox.Terminate(sc, r.vm)
	}); err != nil {
		return fmt.Errorf("end the sandbox of check %s: %w", r.in.CheckID, err)
	}
	r.ended = true
	return nil
}

// terminal are the Checker's own errors that end a check outright. Every
// other error that ends one is a durable operation's, which matches
// *durable.OperationError; the SDK's signal that the invocation is
// suspending matches neither, and must pass through untouched.
var terminal = []error{ErrUnknownAction, ErrBadArguments, ErrBadWait}

// fail closes a check that failed, unless err is the SDK suspending the
// invocation: it ends the sandbox, records a failed step saying which
// action failed, and sets the check's status to failed, each in a step.
// It answers err, with any failure of its own joined.
func (r *run) fail(ctx durable.Context, err error) error {
	var opErr *durable.OperationError
	if !errors.As(err, &opErr) && !slices.ContainsFunc(terminal, func(t error) bool { return errors.Is(err, t) }) {
		return err
	}
	errs := []error{err, r.endSandbox(ctx)}
	// The summary names the action, never the harness's or the SDK's text:
	// the web page shows it.
	summary := fmt.Sprintf("The check failed during %s.", r.current)
	errs = append(errs, r.record(ctx, "failed", outcome{Summary: summary}))
	if _, updateErr := durable.Step(ctx, "record-failure", func(sc durable.StepContext) (bool, error) {
		return true, r.deps.Store.UpdateCheck(sc, r.in.CheckID, store.CheckUpdate{Status: store.StatusFailed})
	}); updateErr != nil {
		errs = append(errs, fmt.Errorf("record check %s as failed: %w", r.in.CheckID, updateErr))
	}
	return errors.Join(errs...)
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
