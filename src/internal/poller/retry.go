package poller

import (
	"context"
	"fmt"

	"github.com/JairJosafath/mcp-customs/src/internal/store"
)

// retryOne starts, once, the retry of package a's re-check that failed,
// when the Checker asked for one (store.MarkRetry) and its version is
// still the newest polled, then clears the ask. It answers whether it
// started the retry. The retry's check ID comes from the package and
// version, apart from the first re-check's, so a poll that runs again
// after its clear was lost starts nothing new; it links to the same
// approved check and version, and says it is the retry, so a second
// failure is recorded rather than retried.
func retryOne(ctx context.Context, d Deps, a store.Approved) (bool, error) {
	if a.Retry == "" {
		return false, nil
	}
	if a.Retry != a.Polled {
		// A newer version was polled since: its re-check covers the package.
		return false, d.Approvals.ClearRetry(ctx, a.Kind, a.Name, a.Retry)
	}
	e := Event{
		CheckID:    RetryID(a.Kind, a.Name, a.Retry),
		Submission: store.Submission{Kind: a.Kind, Ref: a.Name + "@" + a.Retry},
		Recheck:    Link{CheckID: a.CheckID, Ref: a.Name + "@" + a.Version, ToolListHash: a.ToolListHash, Retry: true},
	}
	started, err := start(ctx, d, e)
	if err != nil {
		return false, fmt.Errorf("start the retry %s: %w", e.CheckID, err)
	}
	if err := d.Approvals.ClearRetry(ctx, a.Kind, a.Name, a.Retry); err != nil {
		return false, err
	}
	if started {
		d.Log.InfoContext(ctx, "A failed re-check was started again.", "checkId", e.CheckID, "kind", a.Kind, "ref", e.Submission.Ref, "recheckOf", a.CheckID)
	}
	return started, nil
}

// RetryID is the check ID of the one retry of the re-check of version of
// package kind and name: RecheckID's, marked as the retry.
func RetryID(kind, name, version string) string {
	return RecheckID(kind, name, version) + "-retry"
}
