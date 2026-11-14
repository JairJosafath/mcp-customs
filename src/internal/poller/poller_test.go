package poller

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/JairJosafath/mcp-customs/src/internal/store"
)

func mailApproved() store.Approved {
	return store.Approved{
		Kind: "go", Name: "example.com/mail", Version: "v1.0.0", CheckID: "c0", ToolListHash: "tools-v1", Polled: "v1.0.0",
	}
}

func TestANewVersionOfAnApprovedPackageStartsOneRecheckLinkedToTheApprovedCheck(t *testing.T) {
	approvals := &memoryApprovals{items: []store.Approved{mailApproved()}}
	registry := &fixedRegistry{latest: map[string]string{"go#example.com/mail": "v1.0.1"}}
	starter := &recordingStarter{}
	d := Deps{Approvals: approvals, Registry: registry, Checker: starter, Log: discard()}
	res, err := Poll(t.Context(), d)
	if err != nil {
		t.Fatal(err)
	}
	if res != (Result{Packages: 1, Started: 1}) {
		t.Errorf("result %+v, want one package and one re-check", res)
	}
	want := []Event{{
		CheckID:    RecheckID("go", "example.com/mail", "v1.0.1"),
		Submission: store.Submission{Kind: "go", Ref: "example.com/mail@v1.0.1"},
		Recheck:    Link{CheckID: "c0", Ref: "example.com/mail@v1.0.0", ToolListHash: "tools-v1"},
	}}
	if !reflect.DeepEqual(starter.events, want) {
		t.Errorf("started %+v, want %+v", starter.events, want)
	}
	if approvals.items[0].Polled != "v1.0.1" || approvals.items[0].Version != "v1.0.0" {
		t.Errorf("approval %+v, want v1.0.0 still approved and v1.0.1 polled", approvals.items[0])
	}
	// The next poll finds the version polled and starts nothing.
	res, err = Poll(t.Context(), d)
	if err != nil || res != (Result{Packages: 1}) || len(starter.events) != 1 {
		t.Errorf("second poll %+v, %v, started %d; want nothing new", res, err, len(starter.events))
	}
}

func TestAPollStartsNothingForTheApprovedVersionARemoteServerOrAnUnpublishedPackage(t *testing.T) {
	approvals := &memoryApprovals{items: []store.Approved{
		mailApproved(),
		{Kind: "remote", Name: "https://mcp.example.com/", Version: "x", CheckID: "c1"},
		{Kind: "npm", Name: "gone-mcp", Version: "1.0.0", CheckID: "c2", Polled: "1.0.0"},
	}}
	registry := &fixedRegistry{latest: map[string]string{"go#example.com/mail": "v1.0.0"}}
	starter := &recordingStarter{}
	res, err := Poll(t.Context(), Deps{Approvals: approvals, Registry: registry, Checker: starter, Log: discard()})
	if err != nil || res != (Result{Packages: 2}) {
		t.Errorf("result %+v, %v; want two packages polled and nothing started", res, err)
	}
	if len(starter.events) != 0 || approvals.marks != 0 {
		t.Errorf("started %+v and marked %d", starter.events, approvals.marks)
	}
	if want := []string{"go#example.com/mail", "npm#gone-mcp"}; !reflect.DeepEqual(registry.asked, want) {
		t.Errorf("asked %v, want %v: never a remote server", registry.asked, want)
	}
}

func TestAPollThatRunsAgainAfterItsMarkWasLostStartsNoSecondCheck(t *testing.T) {
	approvals := &memoryApprovals{items: []store.Approved{mailApproved()}}
	registry := &fixedRegistry{latest: map[string]string{"go#example.com/mail": "v1.0.1"}}
	starter := &recordingStarter{}
	d := Deps{Approvals: approvals, Registry: registry, Checker: starter, Log: discard()}
	if _, err := Poll(t.Context(), d); err != nil {
		t.Fatal(err)
	}
	approvals.items[0].Polled = "v1.0.0"
	res, err := Poll(t.Context(), d)
	if err != nil || res.Started != 1 || len(starter.events) != 1 || approvals.items[0].Polled != "v1.0.1" {
		t.Errorf("result %+v, %v, %d started, polled %s; want the check already started and the mark made",
			res, err, len(starter.events), approvals.items[0].Polled)
	}
}

func TestAPackageThatCantBePolledIsCountedAndTheOthersArePolledAllTheSame(t *testing.T) {
	approvals := &memoryApprovals{items: []store.Approved{
		{Kind: "npm", Name: "down-mcp", Version: "1.0.0", CheckID: "c1", Polled: "1.0.0"},
		{Kind: "npm", Name: "odd-mcp", Version: "1.0.0", CheckID: "c2", Polled: "1.0.0"},
		mailApproved(),
	}}
	registry := &fixedRegistry{
		latest: map[string]string{"go#example.com/mail": "v1.0.1", "npm#odd-mcp": "^2.0.0"},
		errs:   map[string]error{"npm#down-mcp": ErrRegistryFailed},
	}
	starter := &recordingStarter{}
	res, err := Poll(t.Context(), Deps{Approvals: approvals, Registry: registry, Checker: starter, Log: discard()})
	if !errors.Is(err, ErrPollFailed) || !strings.Contains(err.Error(), "2 of 3") {
		t.Errorf("error %v, want 2 of 3 failed", err)
	}
	if res != (Result{Packages: 3, Started: 1, Failed: 2}) || len(starter.events) != 1 {
		t.Errorf("result %+v, started %+v; want the mail package re-checked", res, starter.events)
	}
}

func TestAPollWhoseCheckerFailsLeavesThePackageUnmarkedForTheNextPoll(t *testing.T) {
	approvals := &memoryApprovals{items: []store.Approved{mailApproved()}}
	registry := &fixedRegistry{latest: map[string]string{"go#example.com/mail": "v1.0.1"}}
	starter := &recordingStarter{err: errors.New("TooManyRequestsException")}
	res, err := Poll(t.Context(), Deps{Approvals: approvals, Registry: registry, Checker: starter, Log: discard()})
	if !errors.Is(err, ErrPollFailed) || res.Failed != 1 || approvals.marks != 0 {
		t.Errorf("result %+v, %v, %d marks; want a failure and no mark", res, err, approvals.marks)
	}
}

func TestAPollFailsWhenTheApprovalsCantBeRead(t *testing.T) {
	outage := errors.New("ProvisionedThroughputExceededException")
	_, err := Poll(t.Context(), Deps{Approvals: &memoryApprovals{listErr: outage}, Registry: &fixedRegistry{}, Checker: &recordingStarter{}, Log: discard()})
	if !errors.Is(err, outage) {
		t.Errorf("error %v, want the store's", err)
	}
}

func TestARecheckIDIsAValidCheckIDOfThePackageAndVersion(t *testing.T) {
	id := RecheckID("npm", "@acme/weather-mcp", "1.0.1")
	if !store.ValidCheckID(id) || !strings.HasPrefix(id, "recheck-") {
		t.Errorf("RecheckID = %q, want a valid check ID", id)
	}
	if id != RecheckID("npm", "@acme/weather-mcp", "1.0.1") {
		t.Error("RecheckID differs for the same package and version")
	}
	for _, other := range []string{RecheckID("npm", "@acme/weather-mcp", "1.0.2"), RecheckID("pypi", "@acme/weather-mcp", "1.0.1"), RecheckID("npm", "@acme/weather-mc", "p1.0.1")} {
		if other == id {
			t.Errorf("RecheckID gives %q to another package or version", id)
		}
	}
}
