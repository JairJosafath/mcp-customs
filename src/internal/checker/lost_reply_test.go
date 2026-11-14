package checker

import (
	"errors"
	"strings"
	"testing"

	"github.com/JairJosafath/mcp-customs/src/internal/poller"
)

func TestARecheckPassThatCommittedButLostItsReplyStillLiftsTheMark(t *testing.T) {
	// The review's repro: code says review, so c0 is marked; a person
	// approves; the pass commits but its reply is lost, so the verdict step
	// fails on a check that is done, and the mark must still be lifted.
	w := reviewedRecheck()
	w.rec.lostPassReply = errors.New("connection reset")
	approvedRecheck(t, w)
	if c0, _, _ := w.rec.GetCheck(t.Context(), "c0"); c0.SupersededBy != "" {
		t.Errorf("approved check %+v, want the mark lifted", c0)
	}
	if len(w.events.lifted) != 1 || w.events.lifted[0].RecheckID != "recheck-1" {
		t.Errorf("lifted events %+v, want one, from recheck-1", w.events.lifted)
	}
}

func TestARetryPassThatCommittedButLostItsReplyStillLiftsTheMark(t *testing.T) {
	w := reviewedRecheck()
	w.rec.checks[0].SupersededBy = poller.RecheckID("npm", "weather-mcp", "1.0.1")
	w.judge = cleanJudge()
	w.rec.lostPassReply = errors.New("connection reset")
	retry := newVersion(true)
	retry.CheckID = poller.RetryID("npm", "weather-mcp", "1.0.1")
	runFailing(t, w, retry)
	if c0, _, _ := w.rec.GetCheck(t.Context(), "c0"); c0.SupersededBy != "" {
		t.Errorf("approved check %+v, want the failed re-check's mark lifted by its retry", c0)
	}
	if len(w.events.lifted) != 1 || w.events.lifted[0].RecheckID != retry.CheckID {
		t.Errorf("lifted events %+v, want one, from the retry", w.events.lifted)
	}
}

func TestALiftThatFailsAfterALostPassReplyRaisesTheAlarm(t *testing.T) {
	w := reviewedRecheck()
	w.rec.lostPassReply = errors.New("connection reset")
	w.rec.liftErr = errors.New("throttled")
	_, logs := approvedRecheck(t, w)
	if !strings.Contains(logs.String(), `"`+LiftFailedKey+`":1`) || !strings.Contains(logs.String(), LiftFailedLog) {
		t.Errorf("logs %s, want a %q entry with %s 1", logs, LiftFailedLog, LiftFailedKey)
	}
}

func TestAPersonsBlockWhoseDoneReplyIsLostAsksNoRetry(t *testing.T) {
	// A retry here could approve what the person blocked.
	w := reviewedRecheck()
	w.rec.lostDoneReply = errors.New("connection reset")
	decidedRecheck(t, w, DecisionBlock)
	if len(w.rec.retries) != 0 {
		t.Errorf("retries asked %v, want none: a person blocked the re-check", w.rec.retries)
	}
	if c0, _, _ := w.rec.GetCheck(t.Context(), "c0"); c0.SupersededBy != "recheck-1" || len(w.events.superseded) != 1 {
		t.Errorf("approved check %+v, events %+v; want it superseded once", c0, w.events.superseded)
	}
}
