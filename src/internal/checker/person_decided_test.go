package checker

import (
	"errors"
	"strings"
	"testing"

	"github.com/JairJosafath/mcp-customs/src/internal/store"
)

func TestAPersonsBlockWhoseVerdictCantBeWrittenIsNeverRetried(t *testing.T) {
	// The review's repro: a person blocks, and every write of the done
	// verdict fails. A retry would start from nothing and could approve
	// the version the person blocked.
	w := reviewedRecheck()
	w.rec.doneErr = errors.New("throttled")
	_, logs := decidedRecheck(t, w, DecisionBlock)
	if len(w.rec.retries) != 0 {
		t.Fatalf("retries asked %v, want none: a person blocked the re-check", w.rec.retries)
	}
	if c0, _, _ := w.rec.GetCheck(t.Context(), "c0"); c0.SupersededBy != "recheck-1" || c0.RecheckFailed != "recheck-1" {
		t.Errorf("approved check %+v, want it still superseded, and marked as left undecided", c0)
	}
	if len(w.rec.approved) != 0 || len(w.events.lifted) != 0 {
		t.Errorf("approvals %+v, lifted %+v; want the block standing", w.rec.approved, w.events.lifted)
	}
	if !strings.Contains(logs.String(), PersonsVerdictLostLog) || !strings.Contains(logs.String(), `"`+FailedTwiceKey+`":1`) {
		t.Errorf("logs %s, want a %q entry with %s 1", logs, PersonsVerdictLostLog, FailedTwiceKey)
	}
}

func TestAPersonsBlockWhoseVerdictStepFailedIsWrittenAgain(t *testing.T) {
	// The verdict's page step can't be written, so the verdict step never
	// ran: the person's block is written again instead of a retry asked.
	w := reviewedRecheck()
	w.rec.failStep = "verdict"
	decidedRecheck(t, w, DecisionBlock)
	if len(w.rec.retries) != 0 {
		t.Errorf("retries asked %v, want none: a person blocked the re-check", w.rec.retries)
	}
	if check, _, _ := w.rec.GetCheck(t.Context(), "recheck-1"); check.Status != store.StatusDone || check.Verdict != "block" {
		t.Errorf("re-check %+v, want it done with the person's block", check)
	}
	if c0, _, _ := w.rec.GetCheck(t.Context(), "c0"); c0.SupersededBy != "recheck-1" || c0.RecheckFailed != "" {
		t.Errorf("approved check %+v, want it superseded, and not marked", c0)
	}
}
