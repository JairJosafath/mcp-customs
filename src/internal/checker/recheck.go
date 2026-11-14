package checker

import (
	"fmt"

	"github.com/aws/aws-durable-execution-sdk-go/durable"

	"github.com/JairJosafath/mcp-customs/src/internal/store"
)

// Recheck links a check to the approved check of an earlier version of the
// same package: the poller starts one when the package's registry names a
// newer version. A re-check runs in full, probes included, whatever its
// tool list: a rug pull keeps the list and changes what a tool does.
type Recheck struct {
	// CheckID is the check that approved the earlier version.
	CheckID string `json:"checkId"`
	// Ref is the earlier version's ref, as that check was submitted.
	Ref string `json:"ref"`
	// ToolListHash is the tool-list hash that check approved.
	ToolListHash string `json:"toolListSha256"`
	// Retry says this is the one retry of a re-check that failed: its
	// failure is recorded, not retried again.
	Retry bool `json:"retry,omitempty"`
}

// ErrBadRecheck says the event's re-check names no approved check.
var ErrBadRecheck = fmt.Errorf("a re-check must name the approved check, as a check id, and its ref of 1 to %d characters", maxRefLength)

// validRecheck reports whether re, if any, names an approved check.
func validRecheck(re *Recheck) bool {
	return re == nil || (store.ValidCheckID(re.CheckID) && re.Ref != "" && len(re.Ref) <= maxRefLength)
}

// compare records, for a re-check, how its tool list compares with the
// one approved for the earlier version. Code decides nothing from it: the
// server is probed either way.
func (r *run) compare(ctx durable.Context) error {
	re := r.in.Recheck
	if re == nil {
		return nil
	}
	summary := fmt.Sprintf("The tool list is the same as the one check %s approved for %s; the server is probed all the same, since a new version can change what a tool does.", re.CheckID, re.Ref)
	if r.listing.ToolHash != re.ToolListHash {
		summary = fmt.Sprintf("The tool list differs from the one check %s approved for %s.", re.CheckID, re.Ref)
	}
	return r.record(ctx, "compare", outcome{Summary: summary})
}

// approval is the APPROVED item a pass of a package writes, so the poller
// re-checks the package's next version, and whether the write is
// conditional: a re-check writes only while its version is still the newest
// the poller has polled, so a re-check overtaken by a newer version doesn't
// pull the approval back; a fresh submission writes unconditionally. It is
// false for a remote server, which has no versions, or a ref that names none.
func approval(report Report) (a store.Approved, conditional, ok bool) {
	name, version, ok := store.SplitRef(report.Submission.Ref)
	if !ok || report.Submission.Kind == "remote" {
		return store.Approved{}, false, false
	}
	a = store.Approved{
		Kind: report.Submission.Kind, Name: name, Version: version,
		CheckID: report.CheckID, ToolListHash: report.InstallSpec.ToolListHash,
	}
	return a, report.Recheck != nil, true
}
