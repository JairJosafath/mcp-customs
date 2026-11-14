package checker

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/aws/aws-durable-execution-sdk-go/durable"

	"github.com/JairJosafath/mcp-customs/src/internal/store"
	"github.com/JairJosafath/mcp-customs/src/internal/verdict"
)

// finish ends the sandbox and records the verdict's STEP# item, saying
// who decided; then, in one step, it writes the report to the bucket and,
// last, the verdict to the check's META, with the approval of a pass this
// check decided to HASH# and, for a package, to APPROVED in the same
// transaction, so a check reads done only once its report and its verdict
// step are there, and is approved only once it reads done. A verdict step
// that can't be written fails the check before any approval is. A
// re-check that a person approved after code did not pass lifts its
// superseded mark (lift); a lift that fails then is logged, as the pass is
// done, and the log entry raises an alarm (LiftFailedLog).
func (r *run) finish(ctx durable.Context, decided verdict.Result, by string) (verdict.Verdict, error) {
	r.current = "verdict"
	if err := r.endSandbox(ctx); err != nil {
		return "", err
	}
	spec := InstallSpec{Kind: r.in.Submission.Kind, Ref: r.in.Submission.Ref, DependencyHash: r.resolved.Hash, ToolListHash: r.listing.ToolHash}
	report := Report{
		CheckID: r.in.CheckID, Submission: r.in.Submission, Verdict: decided.Verdict, Findings: decided.Findings,
		DecidedBy: by, InstallSpec: spec, Probes: r.probes, Bound: boundNote, Recheck: r.in.Recheck,
	}
	if r.approved != nil && by == "seen before" {
		report.SeenBefore = r.approved.CheckID
	}
	summary := fmt.Sprintf("Verdict: %s, decided by %s, with %d finding(s).", decided.Verdict, by, len(decided.Findings))
	if err := r.record(ctx, "verdict", outcome{Summary: summary, Findings: decided.Findings}); err != nil {
		return "", err
	}
	if _, err := durable.Step(ctx, "verdict", func(sc durable.StepContext) (bool, error) {
		report.DecidedAt = time.Now().UTC()
		return true, r.writeVerdict(sc, report)
	}); err != nil {
		return "", fmt.Errorf("write the verdict of check %s: %w", r.in.CheckID, err)
	}
	if err := r.settleSuperseded(ctx, decided.Verdict); err != nil {
		if decided.Verdict != verdict.Pass {
			r.unsettled = true
			return "", err
		}
		// The pass is done and approved: a lift or its event that fails
		// after it is logged, and the verdict stands.
		ctx.Logger().ErrorContext(ctx, LiftFailedLog, LiftFailedKey, 1,
			"checkId", r.in.CheckID, "error", err.Error())
	}
	return decided.Verdict, nil
}

// writeVerdict writes report, then the check's verdict: for a pass this
// check decided, in one transaction with its approval (store.PassCheck),
// so no approval is left of a check that could not be marked done. Each
// is a whole write a retry repeats.
func (r *run) writeVerdict(sc durable.StepContext, report Report) error {
	raw, err := json.Marshal(report)
	if err != nil {
		return fmt.Errorf("encode the report: %w", err)
	}
	if err := r.deps.Reports.PutReport(sc, r.in.CheckID, raw); err != nil {
		return err
	}
	if report.Verdict != verdict.Pass || report.SeenBefore != "" {
		return r.deps.Store.UpdateCheck(sc, r.in.CheckID, store.CheckUpdate{Status: store.StatusDone, Verdict: string(report.Verdict)})
	}
	spec, err := json.Marshal(report.InstallSpec)
	if err != nil {
		return fmt.Errorf("encode the install spec: %w", err)
	}
	pass := store.Pass{
		Hash:    store.Verdict{Hash: r.resolved.Hash, CheckID: r.in.CheckID, ToolListHash: r.listing.ToolHash, InstallSpec: string(spec)},
		Verdict: string(report.Verdict),
	}
	if a, conditional, ok := approval(report); ok {
		pass.Approved, pass.Conditional = &a, conditional
	}
	return r.deps.Store.PassCheck(sc, pass)
}

// settleSuperseded, once a re-check's verdict is final, supersedes the
// approved check when it did not pass (if code's verdict didn't already),
// and lifts the mark when a person approved it after all.
func (r *run) settleSuperseded(ctx durable.Context, v verdict.Verdict) error {
	if v == verdict.Pass {
		return r.lift(ctx)
	}
	return r.supersede(ctx, v)
}
