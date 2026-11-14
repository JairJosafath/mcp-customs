// Package checker is the Checker's work: a durable execution that runs a
// whole check as registered actions, each one durable operation, and
// decides its verdict by code.
package checker

import (
	"context"
	"encoding/json"
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
	PassCheck(ctx context.Context, p store.Pass) error
	FailCheck(ctx context.Context, id string) error
	MarkRetry(ctx context.Context, kind, name, version string) (bool, error)
	MarkSuperseded(ctx context.Context, approvedID string, s store.Superseding) (bool, error)
	LiftSuperseded(ctx context.Context, approvedID, recheckID string) (bool, error)
}

// Reports is where a check's report and raw observations go: the bucket.
type Reports interface {
	PutReport(ctx context.Context, checkID string, report []byte) error
	PutObservations(ctx context.Context, checkID string, observations []byte) error
	PutOversized(ctx context.Context, checkID, what string, body []byte) error
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
	// Events is where a superseded approval is announced.
	Events Events
	// APIHost is the stack's own API host, API_HOST: no allowlist may hold
	// it, or a name LookupHost resolves to one of its addresses.
	APIHost    string
	LookupHost LookupHost
}

// Input is the event that starts a check.
type Input struct {
	CheckID    string           `json:"checkId"`
	Submission store.Submission `json:"submission"`
	// Recheck, when set, makes this the re-check of a newer version of an
	// approved package.
	Recheck *Recheck `json:"recheck,omitempty"`
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
	// seen are the hosts and files observe found.
	seen seen
	// probeArgs are the judge's arguments for each tool, by its index.
	probeArgs map[int]map[string]any
	// judgeErrs are the judge's failures; any gives review.
	judgeErrs []error
	// turn is the investigation's turn, turns those finished, and outcome
	// the server text the turn's action brought back.
	turn    int
	turns   []Turn
	outcome string
	// current is the action or phase running, for a failure's summary.
	current string
	// oversized is the finding of an answer too large to keep, if any.
	oversized *findings.Finding
	// sealing says the sandbox's egress is being sealed for the last read.
	sealing bool
	// supersedeDone says a re-check's supersede ran.
	supersedeDone bool
	// unsettled says a re-check that did not pass is done but could not
	// supersede the approved check: its failure is still retried.
	unsettled bool
	// ownAPI says allow refused the stack's own API host: the judge
	// investigates nothing after it.
	ownAPI bool
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
		if !validRecheck(in.Recheck) {
			return Output{}, ErrBadRecheck
		}
		check := store.Check{
			ID:           in.CheckID,
			Submission:   in.Submission,
			Status:       store.StatusRunning,
			ExecutionARN: ctx.ExecutionArn(),
		}
		if in.Recheck != nil {
			check.RecheckOf, check.RecheckOfRef = in.Recheck.CheckID, in.Recheck.Ref
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

// check runs the fixed checks and answers the verdict. A server the
// sandbox can't install ends at review, decided by code. A dependency set
// and tool list an earlier check approved pass after resolve, lookup and
// list, except a re-check, which is probed whatever it lists; anything
// else is installed, listed, scanned, probed with the
// judge's arguments, observed, judged and investigated, and a verdict
// short of pass waits for a person.
func (r *run) check(ctx durable.Context) (verdict.Verdict, error) {
	if err := r.do(ctx, ActResolve, nil); err != nil {
		return "", err
	}
	// Nothing was installed, so there is nothing for a person to approve.
	if r.resolved.InstallFailed {
		return r.finish(ctx, verdict.Decide(verdict.Input{Code: r.resolved.Findings}), "code")
	}
	if err := r.do(ctx, ActLookup, nil); err != nil {
		return "", err
	}
	if r.approved != nil && r.in.Recheck == nil {
		if err := r.do(ctx, ActList, nil); err != nil {
			return "", err
		}
		if r.listing.ToolHash == r.approved.ToolListHash {
			return r.finish(ctx, verdict.Result{Verdict: verdict.Pass, Findings: []findings.Finding{}}, "seen before")
		}
	}
	steps := []Action{ActInstall, ActList, ActScan}
	if r.listed {
		steps = slices.DeleteFunc(steps, func(a Action) bool { return a == ActList })
	}
	for _, a := range steps {
		if err := r.do(ctx, a, nil); err != nil {
			return "", err
		}
	}
	if err := r.compare(ctx); err != nil {
		return "", err
	}
	if err := r.writeProbes(ctx); err != nil {
		return "", err
	}
	for _, a := range []Action{ActProbe, ActObserve} {
		if err := r.do(ctx, a, nil); err != nil {
			return "", err
		}
	}
	in, err := r.judge(ctx)
	if err != nil {
		return "", err
	}
	if err := r.sealAndRead(ctx, &in); err != nil {
		return "", err
	}
	decided := verdict.Decide(in)
	if decided.Verdict == verdict.Pass {
		return r.finish(ctx, decided, "code")
	}
	// Anyone using the approved version is told now, not once a person decides.
	if err := r.supersede(ctx, decided.Verdict); err != nil {
		return "", err
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

// judge asks the judge, in a step, sets the sandbox's egress allowlist to
// the hosts it expects for the server's purpose, and lets it investigate.
// It answers what the verdict is decided from: the code findings, and the
// judge's findings and verdict, which only verdict.Decide weighs. A judge
// that fails, or runs out of turns, gives review.
func (r *run) judge(ctx durable.Context) (verdict.Input, error) {
	r.current = "judge"
	evidence := r.evidence()
	j, err := durable.Step(ctx, "judge", func(sc durable.StepContext) (Judgement, error) {
		got, err := r.deps.Judge.Judge(sc, evidence)
		got.ExpectedHosts = slices.DeleteFunc(got.ExpectedHosts, func(h string) bool { return !allowedHost(h) })
		if len(got.ExpectedHosts) > maxHosts {
			got.ExpectedHosts = got.ExpectedHosts[:maxHosts]
		}
		if err == nil && sizeOf(got) > maxStepResult {
			err = fmt.Errorf("%w: the judgement is over %d KB", ErrBadAnswer, maxStepResult>>10)
		}
		return got, err
	}, noRetry)
	var stepErr *durable.StepError
	if err != nil && !errors.As(err, &stepErr) {
		return verdict.Input{}, err
	}
	in := verdict.Input{Model: j.Findings, ModelVerdict: j.Verdict}
	if err != nil {
		r.judgeErrs = append(r.judgeErrs, err)
	}
	in.Code, in.JudgeErr = evidence.Code, errors.Join(r.judgeErrs...)
	summary := fmt.Sprintf("The judge gave %d finding(s) and expects %d host(s); code decides %s so far.", len(j.Findings), len(j.ExpectedHosts), verdict.Decide(in).Verdict)
	if err := r.record(ctx, "judge", outcome{Summary: summary}); err != nil {
		return verdict.Input{}, err
	}
	// A judge that failed has nothing to investigate with.
	if len(r.judgeErrs) > 0 {
		return in, nil
	}
	hosts, err := json.Marshal(allowArgs{Hosts: j.ExpectedHosts})
	if err != nil {
		return verdict.Input{}, fmt.Errorf("encode the allowlist: %w", err)
	}
	if err := r.do(ctx, ActAllow, hosts); err != nil {
		return verdict.Input{}, err
	}
	// An allowlist that reaches the stack's own API ends the investigation
	// before it starts: its finding gives review.
	if r.ownAPI {
		in.Code = unique(r.code)
		return in, nil
	}
	if err := r.investigate(ctx, &in, evidence, j); err != nil {
		return verdict.Input{}, err
	}
	in.Code, in.JudgeErr = unique(r.code), errors.Join(r.judgeErrs...)
	return in, nil
}

// unique is fs with each finding once, in order.
func unique(fs []findings.Finding) []findings.Finding {
	out := make([]findings.Finding, 0, len(fs))
	seen := map[findings.Finding]bool{}
	for _, f := range fs {
		if !seen[f] {
			seen[f] = true
			out = append(out, f)
		}
	}
	return out
}

// endSandbox terminates the check's sandbox, once, in a step. A resolve
// that launched one but never finished, such as one the invocation's
// timeout cut short, left its ID on the check: that one is ended too.
func (r *run) endSandbox(ctx durable.Context) error {
	if r.ended || (r.vm.ID == "" && r.current != string(ActResolve)) {
		return nil
	}
	if _, err := durable.Step(ctx, "end-sandbox", func(sc durable.StepContext) (bool, error) {
		vm := r.vm
		if vm.ID == "" {
			check, found, err := r.deps.Store.GetCheck(sc, r.in.CheckID)
			if err != nil || !found || check.SandboxID == "" {
				return err == nil, err
			}
			vm = sandbox.VM{ID: check.SandboxID}
		}
		return true, r.deps.Sandbox.Terminate(sc, vm)
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
var terminal = []error{ErrUnknownAction, ErrBadArguments, ErrBadWait, ErrTooLarge}

// fail closes a check that failed, unless err is the SDK suspending the
// invocation: it ends the sandbox and sets the check's status to failed,
// each in a step. A check already done keeps its verdict, its approval and
// its page: nothing more is written, and no retry is asked, unless it is a
// re-check that did not pass and left the approved check standing
// (unsettled). Any other check
// gets a failed step saying which action failed, and a re-check is then
// retried once, or its second failure recorded (afterFailedRecheck). It
// answers err, with any failure of its own joined.
func (r *run) fail(ctx durable.Context, err error) error {
	var opErr *durable.OperationError
	if !errors.As(err, &opErr) && !slices.ContainsFunc(terminal, func(t error) bool { return errors.Is(err, t) }) {
		return err
	}
	errs := []error{err, r.endSandbox(ctx)}
	done, updateErr := durable.Step(ctx, "record-failure", func(sc durable.StepContext) (bool, error) {
		failErr := r.deps.Store.FailCheck(sc, r.in.CheckID)
		if errors.Is(failErr, store.ErrCheckDone) {
			return true, nil
		}
		return false, failErr
	})
	if updateErr != nil {
		errs = append(errs, fmt.Errorf("record check %s as failed: %w", r.in.CheckID, updateErr))
	}
	if done && !r.unsettled {
		return errors.Join(errs...)
	}
	errs = append(errs, r.record(ctx, "failed", r.failedOutcome()), r.afterFailedRecheck(ctx))
	return errors.Join(errs...)
}

// failedOutcome is the failed step's outcome. Its summary names the
// action, never the harness's or the SDK's text: the web page shows it.
func (r *run) failedOutcome() outcome {
	if r.oversized != nil {
		return outcome{
			Summary:  fmt.Sprintf("The check failed during %s: the server's answer was larger than a step can keep.", r.current),
			Findings: []findings.Finding{*r.oversized},
		}
	}
	return outcome{Summary: fmt.Sprintf("The check failed during %s.", r.current)}
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
