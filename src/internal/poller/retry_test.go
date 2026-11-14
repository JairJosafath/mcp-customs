package poller

import (
	"errors"
	"reflect"
	"testing"

	"github.com/JairJosafath/mcp-customs/src/internal/store"
)

// failedOnce is the mail package with v1.0.1 polled, whose re-check
// failed and asked for its retry.
func failedOnce() store.Approved {
	a := mailApproved()
	a.Polled, a.Retry = "v1.0.1", "v1.0.1"
	return a
}

func TestAFailedRecheckIsStartedAgainOnceWithANewIDLinkedToTheSameApprovalAndVersion(t *testing.T) {
	approvals := &memoryApprovals{items: []store.Approved{failedOnce()}}
	registry := &fixedRegistry{latest: map[string]string{"go#example.com/mail": "v1.0.1"}}
	starter := &recordingStarter{}
	d := Deps{Approvals: approvals, Registry: registry, Checker: starter, Log: discard()}
	res, err := Poll(t.Context(), d)
	if err != nil || res != (Result{Packages: 1, Retried: 1}) {
		t.Fatalf("Poll = %+v, %v; want one retry", res, err)
	}
	want := []Event{{
		CheckID:    RetryID("go", "example.com/mail", "v1.0.1"),
		Submission: store.Submission{Kind: "go", Ref: "example.com/mail@v1.0.1"},
		Recheck:    Link{CheckID: "c0", Ref: "example.com/mail@v1.0.0", ToolListHash: "tools-v1", Retry: true},
	}}
	if got := starter.started(); !reflect.DeepEqual(got, want) {
		t.Errorf("started %+v, want %+v", got, want)
	}
	if want[0].CheckID == RecheckID("go", "example.com/mail", "v1.0.1") || !store.ValidCheckID(want[0].CheckID) {
		t.Errorf("retry ID %q must be a valid check ID apart from the first re-check's", want[0].CheckID)
	}
	if approvals.items[0].Retry != "" {
		t.Errorf("approval %+v, want the ask cleared", approvals.items[0])
	}
	// The next poll finds no ask and starts nothing.
	res, err = Poll(t.Context(), d)
	if err != nil || res != (Result{Packages: 1}) || len(starter.started()) != 1 {
		t.Errorf("second poll %+v, %v, started %d; want nothing new", res, err, len(starter.started()))
	}
}

func TestARetryWhoseClearWasLostIsNotStartedTwice(t *testing.T) {
	approvals := &memoryApprovals{items: []store.Approved{failedOnce()}}
	starter := &recordingStarter{events: []Event{{CheckID: RetryID("go", "example.com/mail", "v1.0.1")}}}
	d := Deps{Approvals: approvals, Registry: &fixedRegistry{}, Checker: starter, Log: discard()}
	res, err := Poll(t.Context(), d)
	if err != nil || res != (Result{Packages: 1}) || len(starter.started()) != 1 || approvals.items[0].Retry != "" {
		t.Errorf("Poll = %+v, %v, started %d, approval %+v; want no new start and the ask cleared", res, err, len(starter.started()), approvals.items[0])
	}
}

func TestARetryOvertakenByANewerVersionIsDroppedAndTheNewerOneRechecked(t *testing.T) {
	a := failedOnce()
	a.Polled = "v1.0.2"
	approvals := &memoryApprovals{items: []store.Approved{a}}
	registry := &fixedRegistry{latest: map[string]string{"go#example.com/mail": "v1.0.3"}}
	starter := &recordingStarter{}
	res, err := Poll(t.Context(), Deps{Approvals: approvals, Registry: registry, Checker: starter, Log: discard()})
	if err != nil || res != (Result{Packages: 1, Started: 1}) {
		t.Fatalf("Poll = %+v, %v; want only the newer version's re-check", res, err)
	}
	if got := starter.started(); len(got) != 1 || got[0].Recheck.Retry || approvals.items[0].Retry != "" {
		t.Errorf("started %+v, approval %+v; want no retry and the ask cleared", got, approvals.items[0])
	}
}

func TestARetryTheCheckerCantStartIsLeftForTheNextPoll(t *testing.T) {
	approvals := &memoryApprovals{items: []store.Approved{failedOnce()}}
	starter := &recordingStarter{err: errors.New("throttled")}
	res, err := Poll(t.Context(), Deps{Approvals: approvals, Registry: &fixedRegistry{}, Checker: starter, Log: discard()})
	if !errors.Is(err, ErrPollFailed) || res.Failed != 1 || approvals.items[0].Retry != "v1.0.1" {
		t.Errorf("Poll = %+v, %v, approval %+v; want a failure and the ask kept", res, err, approvals.items[0])
	}
}
