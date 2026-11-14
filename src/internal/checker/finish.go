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
// who decided; then, in one step, it writes the report to the bucket, the
// approval of a pass this check decided to HASH# and, for a
// package, to APPROVED, and the verdict to the
// check's META, last, so a check reads done only once its report and its
// verdict step are there. A verdict step that can't be written fails the
// check before any approval is.
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
	return decided.Verdict, nil
}

// writeVerdict writes report, the approval when this check approved the
// server, and the check's verdict, each a whole write a retry repeats.
func (r *run) writeVerdict(sc durable.StepContext, report Report) error {
	raw, err := json.Marshal(report)
	if err != nil {
		return fmt.Errorf("encode the report: %w", err)
	}
	if err := r.deps.Reports.PutReport(sc, r.in.CheckID, raw); err != nil {
		return err
	}
	if report.Verdict == verdict.Pass && report.SeenBefore == "" {
		spec, err := json.Marshal(report.InstallSpec)
		if err != nil {
			return fmt.Errorf("encode the install spec: %w", err)
		}
		if err := r.deps.Store.PutVerdict(sc, store.Verdict{
			Hash: r.resolved.Hash, CheckID: r.in.CheckID, ToolListHash: r.listing.ToolHash, InstallSpec: string(spec),
		}); err != nil {
			return err
		}
		if a, from, ok := approval(report); ok {
			if err := r.deps.Store.PutApproved(sc, a, from); err != nil {
				return err
			}
		}
	}
	return r.deps.Store.UpdateCheck(sc, r.in.CheckID, store.CheckUpdate{Status: store.StatusDone, Verdict: string(report.Verdict)})
}
