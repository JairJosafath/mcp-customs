package poller

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"

	"github.com/JairJosafath/mcp-customs/src/internal/store"
)

// memoryApprovals keeps APPROVED items as the store does, by kind and name.
type memoryApprovals struct {
	mu      sync.Mutex
	items   []store.Approved
	listErr error
	marks   int
}

func (m *memoryApprovals) ListApproved(context.Context) ([]store.Approved, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]store.Approved(nil), m.items...), m.listErr
}

func (m *memoryApprovals) MarkPolled(_ context.Context, kind, name, version string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.marks++
	for i := range m.items {
		if m.items[i].Kind == kind && m.items[i].Name == name {
			m.items[i].Polled = version
			return nil
		}
	}
	return store.ErrNoApproved
}

// fixedRegistry answers each package's latest version from latest, keyed
// kind#name, or its error from errs; a package in neither is unpublished.
type fixedRegistry struct {
	latest map[string]string
	errs   map[string]error

	mu    sync.Mutex
	asked []string
}

func (f *fixedRegistry) Latest(_ context.Context, kind, name string) (string, error) {
	key := kind + "#" + name
	f.mu.Lock()
	f.asked = append(f.asked, key)
	f.mu.Unlock()
	if err, ok := f.errs[key]; ok {
		return "", err
	}
	v, ok := f.latest[key]
	if !ok {
		return "", ErrNotPublished
	}
	return v, nil
}

// askedSet is the packages the registry was asked for, as a set: a poll
// asks them concurrently, so their order is not fixed.
func (f *fixedRegistry) askedSet() map[string]bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := map[string]bool{}
	for _, k := range f.asked {
		out[k] = true
	}
	return out
}

// recordingStarter keeps every event it was asked to start, and answers
// ErrAlreadyStarted for an ID it started before, as Lambda does.
type recordingStarter struct {
	mu     sync.Mutex
	events []Event
	err    error
}

func (r *recordingStarter) Start(_ context.Context, e Event) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.err != nil {
		return r.err
	}
	for _, before := range r.events {
		if before.CheckID == e.CheckID {
			return ErrAlreadyStarted
		}
	}
	r.events = append(r.events, e)
	return nil
}

// started is the events the starter kept.
func (r *recordingStarter) started() []Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]Event(nil), r.events...)
}

// fakeDoer answers a request by its URL from answers, and 404 otherwise;
// it keeps the URLs it was asked.
type fakeDoer struct {
	answers map[string]fakeAnswer
	err     error
	asked   []string
}

type fakeAnswer struct {
	status int
	body   string
}

func (f *fakeDoer) Do(req *http.Request) (*http.Response, error) {
	f.asked = append(f.asked, req.URL.String())
	if f.err != nil {
		return nil, f.err
	}
	a, ok := f.answers[req.URL.String()]
	if !ok {
		a = fakeAnswer{http.StatusNotFound, `{"error":"not found"}`}
	}
	return &http.Response{StatusCode: a.status, Body: io.NopCloser(strings.NewReader(a.body)), Header: http.Header{}}, nil
}

func discard() *slog.Logger { return slog.New(slog.DiscardHandler) }
