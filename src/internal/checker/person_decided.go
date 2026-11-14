package checker

import (
	"errors"
	"fmt"
	"time"

	"github.com/aws/aws-durable-execution-sdk-go/durable"
)

// PersonsVerdictLostLog is the log entry's message that a person decided a
// re-check but its verdict could not be written. It carries FailedTwiceKey,
// so the same alarm goes off: the version is not decided, and it is not
// started again.
const PersonsVerdictLostLog = "A person's verdict on a re-check could not be written."

// errNoReport says a person decided, but the check failed before its
// report was made, so there is no verdict to apply again.
var errNoReport = errors.New("the check failed before its verdict was made")

// reapplyVerdict writes a person's verdict again, in a step with the SDK's
// retries, for a check whose verdict step failed: a retry started from
// nothing doesn't know a person decided, and could approve what they
// blocked. Each write is a whole one, so repeating it is safe.
func (r *run) reapplyVerdict(ctx durable.Context) error {
	if r.report == nil {
		return errNoReport
	}
	report := *r.report
	if _, err := durable.Step(ctx, "reapply-verdict", func(sc durable.StepContext) (bool, error) {
		report.DecidedAt = time.Now().UTC()
		return true, r.writeVerdict(sc, report)
	}); err != nil {
		return fmt.Errorf("write a person's verdict on check %s again: %w", r.in.CheckID, err)
	}
	return nil
}

// personsVerdictLost, for a re-check a person decided whose verdict could
// not be written even again, asks no retry: it marks the approved check
// and logs PersonsVerdictLostLog, which raises the alarm. The approved
// check's superseded mark, set before the person was asked, stays.
func (r *run) personsVerdictLost(ctx durable.Context) error {
	if r.in.Recheck == nil {
		return nil
	}
	return r.markFailedForGood(ctx, "persons-verdict-lost", "verdict-lost", PersonsVerdictLostLog, fmt.Sprintf(
		"A person decided, but the verdict could not be written: the re-check is not started again, check %s says so, and an alarm goes off.", r.in.Recheck.CheckID))
}
