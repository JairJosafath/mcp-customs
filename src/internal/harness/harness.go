// Package harness serves the Harness API (docs/contracts.md): it installs
// the server under test as an unprivileged user whose home looks like a
// developer's, runs it, speaks MCP to it, and records what it does.
package harness

import (
	"context"
	"crypto/sha256"
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

	"github.com/JairJosafath/mcp-customs/src/internal/canary"
	"github.com/JairJosafath/mcp-customs/src/internal/egress"
	"github.com/JairJosafath/mcp-customs/src/internal/ownapi"
)

// Config is what a harness needs to know, read once at start.
type Config struct {
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
	// GoProxy is the GOPROXY-style list a Go install resolves through:
	// the stack's demo proxy, then the public one. Empty keeps Go's own.
	GoProxy string
	// APIHost is the stack's own API host, API_HOST: /allow and /install
	// refuse to allow any name of it. New refuses a host that isn't API
	// Gateway's, an empty one too, so the harness never starts without it.
	APIHost string
	// Now is the clock observations are stamped with.
	Now func() time.Time
	// Egress is the egress proxy the server's traffic goes through, or nil
	// when there is none, as in tests that need no network.
	Egress Egress
	// InstallTimeout bounds one install; CallTimeout one MCP request.
	InstallTimeout time.Duration
	CallTimeout    time.Duration
}

// Egress is what the harness needs of the egress proxy (internal/egress).
type Egress interface {
	// Observe names who is told what the proxy sees.
	Observe(o egress.Observer)
	// SetCanaries names the canaries every request is searched for.
	SetCanaries(c canary.Set)
	// Allow adds hosts to the allowlist and answers the allowlist in force.
	Allow(hosts ...string) []string
	// Env is what the server's environment needs to go through the proxy.
	Env() []string
	// Installing says whether an install runs, which alone may reach the
	// package registries.
	Installing(on bool)
	// Seal empties the allowlist for good and refuses every new connection.
	Seal()
}

// A Harness answers the Harness API for one run, once the /run hook has
// given it the run's token and canaries (lifecycle.go). Calls are answered
// one at a time. Close stops the server under test.
type Harness struct {
	cfg  Config
	api  ownapi.API
	log  *slog.Logger
	obs  *recorder
	mux  *http.ServeMux
	mu   sync.Mutex
	run  *run
	srv  *server
	done bool
	// sealed says /seal has ended egress: /allow is refused after it.
	sealed bool
	life   lifecycle
}

// run is what the install call set up.
type run struct {
	files   *watcher
	command []string
}

// New makes a harness from cfg. It holds no per-run value: the run's token
// and canaries arrive through the /run hook.
func New(cfg Config, log *slog.Logger) (*Harness, error) {
	if cfg.Account.Home == "" || cfg.Workdir == "" || cfg.Installer == nil || cfg.Now == nil {
		return nil, errors.New("the harness needs an account's home, a working directory, an installer and a clock")
	}
	api, err := ownapi.Parse(cfg.APIHost)
	if err != nil {
		return nil, fmt.Errorf("the harness keeps the stack's own API out, and needs its host: %w", err)
	}
	h := &Harness{cfg: cfg, api: api, log: log, obs: &recorder{now: cfg.Now}, mux: http.NewServeMux()}
	h.mux.HandleFunc("POST /install", h.handle(h.install))
	h.mux.HandleFunc("POST /start", h.handle(h.start))
	h.mux.HandleFunc("POST /list", h.handle(h.list))
	h.mux.HandleFunc("POST /call", h.handle(h.call))
	h.mux.HandleFunc("POST /allow", h.handle(h.allow))
	h.mux.HandleFunc("POST /seal", h.handle(h.seal))
	h.mux.HandleFunc("GET /observations", h.handle(h.observations))
	h.mux.HandleFunc("/", h.handle(func(r *http.Request) (int, answer) {
		return problem(http.StatusNotFound, "No call "+r.Method+" "+r.URL.Path+".")
	}))
	if cfg.Egress != nil {
		cfg.Egress.Observe(func(kind string, detail any) { h.obs.add(ObservationKind(kind), detail) })
	}
	return h, nil
}

// ServeHTTP answers one call, after checking its bearer token. Until the
// /run hook has delivered the token, every call answers 503.
func (h *Harness) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch h.life.authorize(r) {
	case notStarted:
		write(w, http.StatusServiceUnavailable, answer{"message": "The run has not started: the /run hook has not delivered its token yet."})
		return
	case unauthorized:
		w.Header().Set("WWW-Authenticate", "Bearer")
		write(w, http.StatusUnauthorized, answer{"message": "This call needs the run's bearer token."})
		return
	case authorized:
	}
	h.mux.ServeHTTP(w, r)
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
	if err := checkHosts(req.AllowHosts); err != nil {
		return problem(http.StatusBadRequest, err.Error())
	}
	if status, body := h.refuseOwnAPI(req.AllowHosts); status != 0 {
		return status, body
	}
	if h.cfg.Egress != nil {
		h.cfg.Egress.Allow(req.AllowHosts...)
	}
	if err := mkdirOwned(h.cfg.Account, h.installTemp()); err != nil {
		return problem(http.StatusInternalServerError, "Could not make the working directory: "+err.Error())
	}
	files := newWatcher(append([]string{h.cfg.Account.Home}, h.cfg.WatchRoots...), h.cfg.Workdir)
	ctx, cancel := context.WithTimeout(r.Context(), h.cfg.InstallTimeout)
	defer cancel()
	installed, err := h.installing(ctx, pkg)
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
	env := h.cfg.Account.env(h.serverPath(), append(append(h.egressEnv(),
		"GOPATH="+filepath.Join(w, ".go"),
		"GOBIN="+filepath.Join(w, "bin"),
		"GOCACHE="+filepath.Join(w, ".cache", "go-build"),
		"GOFLAGS=-modcacherw",
		"npm_config_cache="+filepath.Join(w, ".npm"),
		"PIP_CACHE_DIR="+filepath.Join(w, ".cache", "pip"),
		"TMPDIR="+h.installTemp(),
	), goProxyEnv(h.cfg.GoProxy)...)...)
	return Sandbox{
		Workdir: w,
		Env:     env,
		// The harness's own commands (cat, go, npm) are found on the trusted
		// PATH, never on the server's, whose first directories the package
		// being installed writes.
		Run: func(ctx context.Context, args []string, out io.Writer) error {
			trusted, err := resolve(args, h.cfg.Path)
			if err != nil {
				return err
			}
			return h.cfg.Account.run(ctx, w, env, trusted, out)
		},
		KillAll: h.cfg.Account.killAll,
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
	srv, err := startServer(h.cfg.Account, h.cfg.Workdir, h.cfg.Account.env(h.serverPath(), h.egressEnv()...), command, h.obs.add)
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

// egressEnv is what the server's environment needs for the egress proxy.
func (h *Harness) egressEnv() []string {
	if h.cfg.Egress == nil {
		return nil
	}
	return h.cfg.Egress.Env()
}

type allowRequest struct {
	Hosts []string `json:"hosts"`
}

// allow adds hosts to the egress allowlist and answers the allowlist now in
// force.
func (h *Harness) allow(r *http.Request) (int, answer) {
	var req allowRequest
	if err := decode(r, &req); err != nil {
		return problem(http.StatusBadRequest, err.Error())
	}
	if err := checkHosts(req.Hosts); err != nil {
		return problem(http.StatusBadRequest, err.Error())
	}
	if status, body := h.refuseOwnAPI(req.Hosts); status != 0 {
		return status, body
	}
	if h.cfg.Egress == nil {
		return problem(http.StatusConflict, "This harness has no egress proxy.")
	}
	if h.sealed {
		return problem(http.StatusConflict, "Egress is sealed; no host can be allowed.")
	}
	return http.StatusOK, answer{"hosts": h.cfg.Egress.Allow(req.Hosts...)}
}

// canaryList is the run's canaries as internal/canary has them.
func canaryList(list []Canary) canary.Set {
	set := make(canary.Set, 0, len(list))
	for _, c := range list {
		set = append(set, canary.Canary{Kind: canary.Kind(c.Kind), Value: c.Value})
	}
	return set
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
