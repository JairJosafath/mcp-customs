package poller

import (
	"context"
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
	if got := starter.started(); !reflect.DeepEqual(got, want) {
		t.Errorf("started %+v, want %+v", got, want)
	}
	if approvals.items[0].Polled != "v1.0.1" || approvals.items[0].Version != "v1.0.0" {
		t.Errorf("approval %+v, want v1.0.0 still approved and v1.0.1 polled", approvals.items[0])
	}
	// The next poll finds the version polled and starts nothing.
	res, err = Poll(t.Context(), d)
	if err != nil || res != (Result{Packages: 1}) || len(starter.started()) != 1 {
		t.Errorf("second poll %+v, %v, started %d; want nothing new", res, err, len(starter.started()))
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
	if len(starter.started()) != 0 || approvals.marks != 0 {
		t.Errorf("started %+v and marked %d", starter.started(), approvals.marks)
	}
	if want := map[string]bool{"go#example.com/mail": true, "npm#gone-mcp": true}; !reflect.DeepEqual(registry.askedSet(), want) {
		t.Errorf("asked %v, want %v: never a remote server", registry.askedSet(), want)
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
	// The check was already started, so this poll starts nothing new and
	// counts no start, but it marks the version polled again.
	if err != nil || res != (Result{Packages: 1}) || len(starter.started()) != 1 || approvals.items[0].Polled != "v1.0.1" {
		t.Errorf("result %+v, %v, %d started, polled %s; want no new start and the mark made",
			res, err, len(starter.started()), approvals.items[0].Polled)
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
	if res != (Result{Packages: 3, Started: 1, Failed: 2}) || len(starter.started()) != 1 {
		t.Errorf("result %+v, started %+v; want the mail package re-checked", res, starter.started())
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

// blockingRegistry answers every package with one version, but holds the
// first lookup until release is closed, so a test can prove the other
// packages are polled while one registry call is still in flight.
type blockingRegistry struct {
	version string
	once    chan struct{}
	release chan struct{}
	asked   chan string
}

func (b *blockingRegistry) Latest(_ context.Context, kind, name string) (string, error) {
	b.asked <- kind + "#" + name
	select {
	case <-b.once:
		<-b.release // the first caller waits for the test
	default:
	}
	return b.version, nil
}

func TestASlowRegistryDoesNotStarveTheOtherPackages(t *testing.T) {
	const n = 5
	items := make([]store.Approved, n)
	for i := range items {
		items[i] = store.Approved{Kind: "npm", Name: "pkg-" + string(rune('a'+i)), Version: "1.0.0", CheckID: "c", Polled: "1.0.0"}
	}
	reg := &blockingRegistry{version: "1.0.1", once: make(chan struct{}), release: make(chan struct{}), asked: make(chan string, n)}
	close(reg.once) // the first lookup to arrive will block on release
	done := make(chan Result, 1)
	go func() {
		res, _ := Poll(t.Context(), Deps{Approvals: &memoryApprovals{items: items}, Registry: reg, Checker: &recordingStarter{}, Log: discard()})
		done <- res
	}()
	// All n packages are asked even though one lookup is still blocked:
	// serial polling would stop after the first.
	for range n {
		<-reg.asked
	}
	close(reg.release)
	if res := <-done; res.Packages != n || res.Started != n {
		t.Errorf("result %+v, want all %d packages polled and re-checked", res, n)
	}
}
