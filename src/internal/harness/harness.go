// Package harness serves the Harness API (docs/contracts.md): it installs
// the server under test as an unprivileged user whose home looks like a
// developer's, runs it, speaks MCP to it, and records what it does.
package harness

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Config is what a harness needs to know, read once at start.
type Config struct {
	// Token is the run's bearer token; every call must carry it.
	Token string
	// Account is the unprivileged user the server runs as.
	Account Account
	// Workdir is the server's working directory, where it is installed.
	// It should be inside the account's home.
	Workdir string
	// WatchRoots are the directories where files the server writes are
	// observed, besides the account's home. Workdir is never watched.
	WatchRoots []string
	// Path is the PATH the server's tools come from.
	Path string
	// Installer installs the server.
	Installer Installer
	// Now is the clock observations are stamped with.
	Now func() time.Time
	// InstallTimeout bounds one install; CallTimeout one MCP request.
	InstallTimeout time.Duration
	CallTimeout    time.Duration
}

// A Harness answers the Harness API for one run. Calls are answered one at
// a time. Close stops the server under test.
type Harness struct {
	cfg  Config
	log  *slog.Logger
	obs  *recorder
	mux  *http.ServeMux
	mu   sync.Mutex
	run  *run
	srv  *server
	done bool
}

// run is what the install call set up.
type run struct {
	files   *watcher
	command []string
}

// New makes a harness from cfg. It refuses an empty token.
func New(cfg Config, log *slog.Logger) (*Harness, error) {
	if cfg.Token == "" {
		return nil, errors.New("the harness needs the run's bearer token")
	}
	if cfg.Account.Home == "" || cfg.Workdir == "" || cfg.Installer == nil || cfg.Now == nil {
		return nil, errors.New("the harness needs an account's home, a working directory, an installer and a clock")
	}
	h := &Harness{cfg: cfg, log: log, obs: &recorder{now: cfg.Now}, mux: http.NewServeMux()}
	h.mux.HandleFunc("POST /install", h.handle(h.install))
	h.mux.HandleFunc("POST /start", h.handle(h.start))
	h.mux.HandleFunc("POST /list", h.handle(h.list))
	h.mux.HandleFunc("POST /call", h.handle(h.call))
	h.mux.HandleFunc("GET /observations", h.handle(h.observations))
	h.mux.HandleFunc("/", h.handle(func(r *http.Request) (int, answer) {
		return problem(http.StatusNotFound, "No call "+r.Method+" "+r.URL.Path+".")
	}))
	return h, nil
}

// ServeHTTP answers one call, after checking its bearer token.
func (h *Harness) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !h.authorized(r) {
		w.Header().Set("WWW-Authenticate", "Bearer")
		write(w, http.StatusUnauthorized, answer{"message": "This call needs the run's bearer token."})
		return
	}
	h.mux.ServeHTTP(w, r)
}

func (h *Harness) authorized(r *http.Request) bool {
	got, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	return ok && subtle.ConstantTimeCompare([]byte(got), []byte(h.cfg.Token)) == 1
}

// Close stops the server under test, if it runs. Calls after it answer 503.
func (h *Harness) Close() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.done = true
	if h.srv != nil {
		h.srv.close()
		h.srv = nil
	}
}

// answer is a JSON response body.
type answer map[string]any

// handle answers a call with fn's answer and the observations made since
// the last call, files the server wrote among them.
func (h *Harness) handle(fn func(*http.Request) (int, answer)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		h.mu.Lock()
		defer h.mu.Unlock()
		var status int
		var body answer
		if h.done {
			status, body = problem(http.StatusServiceUnavailable, "The harness is stopping.")
		} else {
			status, body = fn(r)
		}
		if status >= http.StatusInternalServerError {
			h.log.ErrorContext(r.Context(), "A call failed.", "call", r.Method+" "+r.URL.Path, "status", status, "error", body["message"])
		}
		h.noteFiles()
		if _, ok := body["observations"]; !ok {
			body["observations"] = h.obs.fresh()
		}
		write(w, status, body)
	}
}

func (h *Harness) noteFiles() {
	if h.run == nil {
		return
	}
	for _, f := range h.run.files.changes() {
		h.obs.add(ObservedFile, f)
	}
}

type installRequest struct {
	Kind       string   `json:"kind"`
	Ref        string   `json:"ref"`
	Canaries   []Canary `json:"canaries"`
	AllowHosts []string `json:"allowHosts"`
}

func (h *Harness) install(r *http.Request) (int, answer) {
	var req installRequest
	if err := decode(r, &req); err != nil {
		return problem(http.StatusBadRequest, err.Error())
	}
	if h.run != nil {
		return problem(http.StatusConflict, "The server is installed already; a run installs once.")
	}
	pkg, err := ParsePackage(req.Kind, req.Ref)
	if err != nil {
		return problem(http.StatusBadRequest, err.Error())
	}
	canaries, err := canarySet(req.Canaries)
	if err != nil {
		return problem(http.StatusBadRequest, err.Error())
	}
	for _, host := range req.AllowHosts {
		if host == "" || strings.ContainsAny(host, "/ ") {
			return problem(http.StatusBadRequest, fmt.Sprintf("%q is not a host name", host))
		}
	}
	if err := plantHome(h.cfg.Account, canaries); err != nil {
		return problem(http.StatusInternalServerError, "Could not plant the developer's home: "+err.Error())
	}
	if err := mkdirOwned(h.cfg.Account, h.installTemp()); err != nil {
		return problem(http.StatusInternalServerError, "Could not make the working directory: "+err.Error())
	}
	files := newWatcher(append([]string{h.cfg.Account.Home}, h.cfg.WatchRoots...), h.cfg.Workdir)
	ctx, cancel := context.WithTimeout(r.Context(), h.cfg.InstallTimeout)
	defer cancel()
	installed, err := h.cfg.Installer.Install(ctx, pkg, h.sandbox())
	// From here on, files written outside the working directory are observed,
	// the install's own included.
	h.run = &run{files: files, command: installed.Command}
	if err != nil {
		status, body := problem(http.StatusUnprocessableEntity, "The install failed: "+err.Error())
		body["log"] = installed.Log
		return status, body
	}
	sum := sha256.Sum256(installed.Resolved)
	return http.StatusOK, answer{
		"log":          installed.Log,
		"dependencies": string(installed.Resolved),
		"sha256":       hex.EncodeToString(sum[:]),
	}
}

// sandbox is where the installer works: as the account, in the working
// directory, with the server's environment and the ecosystems' caches and
// temporary files kept in the working directory.
func (h *Harness) sandbox() Sandbox {
	w := h.cfg.Workdir
	env := h.cfg.Account.env(h.serverPath(),
		"GOPATH="+filepath.Join(w, ".go"),
		"GOBIN="+filepath.Join(w, "bin"),
		"GOCACHE="+filepath.Join(w, ".cache", "go-build"),
		"GOFLAGS=-modcacherw",
		"npm_config_cache="+filepath.Join(w, ".npm"),
		"PIP_CACHE_DIR="+filepath.Join(w, ".cache", "pip"),
		"TMPDIR="+h.installTemp(),
	)
	return Sandbox{
		Workdir: w,
		Env:     env,
		Run: func(ctx context.Context, args []string, out io.Writer) error {
			return h.cfg.Account.run(ctx, w, env, args, out)
		},
	}
}

// installTemp is the installs' temporary directory, inside the working
// directory, so the build files of an install are not observed as writes.
func (h *Harness) installTemp() string {
	return filepath.Join(h.cfg.Workdir, ".tmp")
}

// serverPath puts the installed commands first, as a developer's shell would.
func (h *Harness) serverPath() string {
	w := h.cfg.Workdir
	return strings.Join([]string{
		filepath.Join(w, "bin"),
		filepath.Join(w, "node_modules", ".bin"),
		filepath.Join(w, "venv", "bin"),
		h.cfg.Path,
	}, string(os.PathListSeparator))
}

type startRequest struct {
	Command []string `json:"command"`
}

func (h *Harness) start(r *http.Request) (int, answer) {
	var req startRequest
	if err := decode(r, &req); err != nil {
		return problem(http.StatusBadRequest, err.Error())
	}
	switch {
	case h.run == nil:
		return problem(http.StatusConflict, "Install the server before starting it.")
	case h.srv != nil:
		return problem(http.StatusConflict, "The server runs already.")
	}
	command := req.Command
	if len(command) == 0 {
		command = h.run.command
	}
	if len(command) == 0 || command[0] == "" {
		return problem(http.StatusBadRequest, "The install named no command; give one.")
	}
	srv, err := startServer(h.cfg.Account, h.cfg.Workdir, h.cfg.Account.env(h.serverPath()), command, h.obs.add)
	if err != nil {
		return problem(http.StatusBadGateway, err.Error())
	}
	ctx, cancel := context.WithTimeout(r.Context(), h.cfg.CallTimeout)
	defer cancel()
	result, err := srv.conn.initialize(ctx)
	if err != nil {
		srv.close()
		status, body := problem(http.StatusBadGateway, "The server did not initialize: "+err.Error())
		body["stderr"] = srv.stderr.String()
		return status, body
	}
	srv.initial = result
	h.srv = srv
	return http.StatusOK, answer{"initialize": result}
}

func (h *Harness) list(r *http.Request) (int, answer) {
	var req struct{}
	if err := decode(r, &req); err != nil {
		return problem(http.StatusBadRequest, err.Error())
	}
	if h.srv == nil {
		return problem(http.StatusConflict, "Start the server before listing.")
	}
	ctx, cancel := context.WithTimeout(r.Context(), h.cfg.CallTimeout)
	defer cancel()
	var caps struct {
		Capabilities map[string]json.RawMessage `json:"capabilities"`
	}
	_ = json.Unmarshal(h.srv.initial, &caps)
	body := answer{}
	for _, l := range []struct{ capability, method, field string }{
		{"tools", "tools/list", "tools"},
		{"resources", "resources/list", "resources"},
		{"prompts", "prompts/list", "prompts"},
	} {
		// Tools are always asked for; a server may serve them without saying.
		if _, ok := caps.Capabilities[l.capability]; !ok && l.capability != "tools" {
			body[l.field] = []json.RawMessage{}
			continue
		}
		items, err := h.srv.conn.list(ctx, l.method, l.field)
		if err != nil {
			return h.serverFailed(l.method, err)
		}
		body[l.field] = items
	}
	return http.StatusOK, body
}

type callRequest struct {
	Tool      string          `json:"tool"`
	Arguments json.RawMessage `json:"arguments"`
}

func (h *Harness) call(r *http.Request) (int, answer) {
	var req callRequest
	if err := decode(r, &req); err != nil {
		return problem(http.StatusBadRequest, err.Error())
	}
	if req.Tool == "" {
		return problem(http.StatusBadRequest, "Name the tool to call.")
	}
	args := req.Arguments
	if len(args) == 0 || string(args) == "null" {
		args = json.RawMessage(`{}`)
	}
	var obj map[string]json.RawMessage
	if json.Unmarshal(args, &obj) != nil {
		return problem(http.StatusBadRequest, "The arguments must be a JSON object.")
	}
	if h.srv == nil {
		return problem(http.StatusConflict, "Start the server before calling a tool.")
	}
	ctx, cancel := context.WithTimeout(r.Context(), h.cfg.CallTimeout)
	defer cancel()
	result, err := h.srv.conn.call(ctx, "tools/call", map[string]any{"name": req.Tool, "arguments": args})
	if rpcErr, ok := errors.AsType[*RPCError](err); ok {
		return http.StatusOK, answer{"error": rpcErr}
	}
	if err != nil {
		return h.serverFailed("tools/call", err)
	}
	return http.StatusOK, answer{"result": result}
}

// serverFailed answers a request the server didn't answer: it stopped, sent
// nonsense, or ran out of time.
func (h *Harness) serverFailed(method string, err error) (int, answer) {
	status, body := problem(http.StatusBadGateway, fmt.Sprintf("The server failed %s: %v", method, err))
	body["stderr"] = h.srv.stderr.String()
	return status, body
}

func (h *Harness) observations(*http.Request) (int, answer) {
	return http.StatusOK, answer{"observations": h.obs.all()}
}

// maxBody bounds a call's body.
const maxBody = 1 << 20

// decode reads a call's JSON body into v, refusing unknown fields. An empty
// body reads as {}.
func decode(r *http.Request, v any) error {
	dec := json.NewDecoder(http.MaxBytesReader(nil, r.Body, maxBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil && !errors.Is(err, io.EOF) {
		return fmt.Errorf("the body is not the call's JSON: %w", err)
	}
	return nil
}

func problem(status int, message string) (int, answer) {
	return status, answer{"message": message}
}

func write(w http.ResponseWriter, status int, body answer) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
