package harness

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
)

// HooksPrefix is where Lambda MicroVMs' lifecycle hooks are served, on
// HOOKS_PORT (docs/contracts.md, "The MicroVM").
const HooksPrefix = "/aws/lambda-microvms/runtime/v1/"

// maxRunHookPayload is the largest run hook payload Lambda delivers.
const maxRunHookPayload = 16 << 10

// maxHookBody bounds a hook's body: the payload, JSON-escaped, and its
// envelope.
const maxHookBody = 8 * maxRunHookPayload

// ObservedHook is a lifecycle hook called after the run started. Lambda
// calls none then, so whoever calls one is inside the MicroVM: the server
// under test.
const ObservedHook ObservationKind = "hook"

// HookDetail is a hook observation's detail.
type HookDetail struct {
	Method string `json:"method"`
	Path   string `json:"path"`
	From   string `json:"from"`
	Status int    `json:"status"`
}

// lifecycle is where the run is in Lambda's lifecycle: the image built
// and snapshotted with no per-run value, then one /run with the token and
// canaries. It has its own lock, apart from the Harness API's: a hook
// called by the server while a call waits on it must not wait for that
// call.
type lifecycle struct {
	mu        sync.Mutex
	listening bool
	token     string
}

// access is what a call's credentials allow.
type access int

const (
	notStarted access = iota
	unauthorized
	authorized
)

// authorize checks r's bearer token against the run's.
func (l *lifecycle) authorize(r *http.Request) access {
	l.mu.Lock()
	token := l.token
	l.mu.Unlock()
	if token == "" {
		return notStarted
	}
	got, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok || subtle.ConstantTimeCompare([]byte(got), []byte(token)) != 1 {
		return unauthorized
	}
	return authorized
}

func (l *lifecycle) started() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.token != ""
}

// Listening tells the harness the Harness API listens, so /ready answers
// 200 and Lambda may snapshot it.
func (h *Harness) Listening() {
	h.life.mu.Lock()
	defer h.life.mu.Unlock()
	h.life.listening = true
}

// Hooks is the handler for Lambda's lifecycle hooks, served on HOOKS_PORT.
// Every hook called once the run has started is refused or answered as
// before, and recorded as an observation.
func (h *Harness) Hooks() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST "+HooksPrefix+"ready", h.ready)
	mux.HandleFunc("POST "+HooksPrefix+"run", h.runHook)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		write(w, http.StatusNotFound, answer{"message": "No hook " + r.Method + " " + r.URL.Path + "."})
	})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		after := h.life.started()
		rec := &statusWriter{ResponseWriter: w, status: http.StatusOK}
		mux.ServeHTTP(rec, r)
		if observeHook(after, r.URL.Path, rec.status) {
			h.obs.add(ObservedHook, HookDetail{Method: r.Method, Path: r.URL.Path, From: r.RemoteAddr, Status: rec.status})
		}
	})
}

// observeHook says whether a hook call is observed: every call made once
// the run had started, and a /run refused because another /run won a race
// while this one waited.
func observeHook(after bool, path string, status int) bool {
	return after || (path == HooksPrefix+"run" && status == http.StatusConflict)
}

// ready answers Lambda's /ready hook at image build: 200 once the Harness
// API listens, 503 to be asked again.
func (h *Harness) ready(w http.ResponseWriter, _ *http.Request) {
	h.life.mu.Lock()
	listening := h.life.listening
	h.life.mu.Unlock()
	if !listening {
		write(w, http.StatusServiceUnavailable, answer{"message": "The Harness API does not listen yet."})
		return
	}
	write(w, http.StatusOK, answer{"message": "Ready."})
}

// runHookBody is what Lambda posts to /run when a MicroVM starts.
type runHookBody struct {
	MicrovmID      string `json:"microvmId"`
	RunHookPayload string `json:"runHookPayload"`
}

// runPayload is the run hook payload the Checker sends.
type runPayload struct {
	Token    string   `json:"token"`
	Canaries []Canary `json:"canaries"`
}

// runHook takes the run's token and canaries, exactly once: it plants the
// home from the canaries, then keeps the token, so the Harness API answers
// only once the home is ready. A second /run, which only something inside
// the MicroVM can send, is refused.
func (h *Harness) runHook(w http.ResponseWriter, r *http.Request) {
	h.life.mu.Lock()
	defer h.life.mu.Unlock()
	if h.life.token != "" {
		write(w, http.StatusConflict, answer{"message": "The run has started already; a MicroVM runs once."})
		return
	}
	payload, canaries, err := decodeRunHook(r)
	if err != nil {
		write(w, http.StatusBadRequest, answer{"message": err.Error()})
		return
	}
	if err := plantHome(h.cfg.Account, canaries); err != nil {
		h.log.ErrorContext(r.Context(), "The /run hook failed.", "error", err.Error())
		write(w, http.StatusInternalServerError, answer{"message": "Could not plant the developer's home."})
		return
	}
	h.life.token = payload.Token
	write(w, http.StatusOK, answer{"message": "The run has started."})
}

// decodeRunHook reads /run's body and the payload in it.
func decodeRunHook(r *http.Request) (runPayload, map[CanaryKind]string, error) {
	var body runHookBody
	if err := json.NewDecoder(http.MaxBytesReader(nil, r.Body, maxHookBody)).Decode(&body); err != nil {
		return runPayload{}, nil, fmt.Errorf("the body is not the run hook's JSON: %w", err)
	}
	if len(body.RunHookPayload) > maxRunHookPayload {
		return runPayload{}, nil, errors.New("the run hook payload is larger than 16 KB")
	}
	var p runPayload
	dec := json.NewDecoder(strings.NewReader(body.RunHookPayload))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return runPayload{}, nil, fmt.Errorf("the run hook payload is not {\"token\",\"canaries\"}: %w", err)
	}
	if p.Token == "" {
		return runPayload{}, nil, errors.New("the run hook payload has no token")
	}
	canaries, err := canarySet(p.Canaries)
	if err != nil {
		return runPayload{}, nil, err
	}
	return p, canaries, nil
}

// statusWriter remembers the status a handler answered.
type statusWriter struct {
	http.ResponseWriter
	status int
}

func (s *statusWriter) WriteHeader(status int) {
	s.status = status
	s.ResponseWriter.WriteHeader(status)
}
