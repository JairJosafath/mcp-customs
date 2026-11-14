// Package poller re-checks approved packages: on a schedule it asks each
// package's registry for its latest version and, when that is one no
// check has seen, starts a check of it linked to the approved one.
// Package versions can't change, so a rug pull is a new version.
package poller

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"sync"

	"github.com/JairJosafath/mcp-customs/src/internal/harness"
	"github.com/JairJosafath/mcp-customs/src/internal/store"
)

// maxConcurrent bounds how many packages a poll works on at once, so one
// slow registry can't starve the rest within the poll's time budget while
// the Checker isn't flooded with starts.
const maxConcurrent = 8

// Approvals is the store's calls the poller makes.
type Approvals interface {
	ListApproved(ctx context.Context) ([]store.Approved, error)
	MarkPolled(ctx context.Context, kind, name, version string) error
	ClearRetry(ctx context.Context, kind, name, version string) error
}

// Registry answers a package's latest version, and ErrNotPublished when
// the registry has none.
type Registry interface {
	Latest(ctx context.Context, kind, name string) (string, error)
}

// Starter starts a check on the Checker, and answers ErrAlreadyStarted
// when one with the same ID was started before.
type Starter interface {
	Start(ctx context.Context, e Event) error
}

// ErrAlreadyStarted says the check was started before: a poll that ran
// again, after its mark was lost.
var ErrAlreadyStarted = errors.New("the check was already started")

// ErrNotPublished says the registry has no such package, or no version of it.
var ErrNotPublished = errors.New("the registry has no version of the package")

// Event starts a re-check: the Checker's Input.
type Event struct {
	CheckID    string           `json:"checkId"`
	Submission store.Submission `json:"submission"`
	Recheck    Link             `json:"recheck"`
}

// Link names the approved check a re-check follows, as the Checker's
// Recheck takes it.
type Link struct {
	CheckID      string `json:"checkId"`
	Ref          string `json:"ref"`
	ToolListHash string `json:"toolListSha256"`
	// Retry says this is the one retry of a re-check that failed.
	Retry bool `json:"retry,omitempty"`
}

// Deps are what a poll works with.
type Deps struct {
	Approvals Approvals
	Registry  Registry
	Checker   Starter
	Log       *slog.Logger
}

// Result is what a poll did: the packages it looked at, the re-checks it
// started, the failed re-checks it started again, and the packages it
// couldn't poll.
type Result struct {
	Packages int `json:"packages"`
	Started  int `json:"started"`
	Retried  int `json:"retried"`
	Failed   int `json:"failed"`
}

// Poll looks at every approved package once. A re-check that failed and
// asked for its retry is started again first (retryOne). A package whose latest
// version is neither the approved one nor one a re-check was started for
// gets a re-check, started once: its check ID comes from the package and
// version, so a poll that runs again starts nothing new. A remote server
// has no versions and is left alone. Packages are polled concurrently, at
// most maxConcurrent at once, so one slow registry can't starve the rest.
// A package it can't poll is logged and counted, the others polled all the
// same, and the poll answers an error naming how many failed.
func Poll(ctx context.Context, d Deps) (Result, error) {
	approved, err := d.Approvals.ListApproved(ctx)
	if err != nil {
		return Result{}, fmt.Errorf("list the approved packages: %w", err)
	}
	var (
		mu  sync.Mutex
		res Result
		wg  sync.WaitGroup
	)
	sem := make(chan struct{}, maxConcurrent)
	for _, a := range approved {
		if a.Kind == "remote" {
			continue
		}
		sem <- struct{}{}
		wg.Go(func() {
			defer func() { <-sem }()
			retried, err := retryOne(ctx, d, a)
			started := false
			if err == nil {
				started, err = pollOne(ctx, d, a)
			}
			mu.Lock()
			defer mu.Unlock()
			res.Packages++
			if retried {
				res.Retried++
			}
			switch {
			case err != nil:
				res.Failed++
				d.Log.WarnContext(ctx, "A package could not be polled.", "kind", a.Kind, "name", a.Name, "error", err.Error())
			case started:
				res.Started++
			}
		})
	}
	wg.Wait()
	if res.Failed > 0 {
		return res, fmt.Errorf("poll %d of %d approved packages: %w", res.Failed, res.Packages, ErrPollFailed)
	}
	return res, nil
}

// ErrPollFailed says some packages could not be polled; the log names them.
var ErrPollFailed = errors.New("the registry or the Checker failed")

// pollOne polls package a, and answers whether it started a re-check.
func pollOne(ctx context.Context, d Deps, a store.Approved) (bool, error) {
	latest, err := d.Registry.Latest(ctx, a.Kind, a.Name)
	if errors.Is(err, ErrNotPublished) {
		d.Log.InfoContext(ctx, "The registry has no version of an approved package.", "kind", a.Kind, "name", a.Name)
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if latest == a.Version || latest == a.Polled {
		return false, nil
	}
	ref := a.Name + "@" + latest
	if _, err := harness.ParsePackage(a.Kind, ref); err != nil {
		return false, fmt.Errorf("the registry's latest version is not one pinned version: %w", err)
	}
	e := Event{
		CheckID:    RecheckID(a.Kind, a.Name, latest),
		Submission: store.Submission{Kind: a.Kind, Ref: ref},
		Recheck:    Link{CheckID: a.CheckID, Ref: a.Name + "@" + a.Version, ToolListHash: a.ToolListHash},
	}
	started, err := start(ctx, d, e)
	if err != nil {
		return false, fmt.Errorf("start re-check %s: %w", e.CheckID, err)
	}
	if err := d.Approvals.MarkPolled(ctx, a.Kind, a.Name, latest); err != nil {
		return false, err
	}
	if !started {
		return false, nil
	}
	d.Log.InfoContext(ctx, "A re-check started.", "checkId", e.CheckID, "kind", a.Kind, "ref", ref, "recheckOf", a.CheckID)
	return true, nil
}

// start starts e on the Checker and answers whether it is a new start. A
// poll that already ran for the check finds it started (same ID): it is
// not a new start, and not an error.
func start(ctx context.Context, d Deps, e Event) (bool, error) {
	err := d.Checker.Start(ctx, e)
	if errors.Is(err, ErrAlreadyStarted) {
		return false, nil
	}
	return err == nil, err
}

// RecheckID is the check ID of the re-check of version of package kind
// and name: the same every time, so it is started once.
func RecheckID(kind, name, version string) string {
	sum := sha256.Sum256([]byte(kind + "\x00" + name + "\x00" + version))
	return "recheck-" + hex.EncodeToString(sum[:20])
}
