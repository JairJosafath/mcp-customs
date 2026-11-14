package harness

import (
	"bytes"
	"encoding/json"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// runHookRequest is the body Lambda posts to /run, with token and canaries
// as the run hook payload.
func runHookRequest(t *testing.T, token string, canaries []Canary) map[string]any {
	t.Helper()
	payload, err := json.Marshal(map[string]any{"token": token, "canaries": canaries})
	if err != nil {
		t.Fatal(err)
	}
	return map[string]any{"microvmId": "mvm-0123456789abcdef", "runHookPayload": string(payload)}
}

// hook calls one of the lifecycle hooks, as Lambda would on HOOKS_PORT.
func (r testRun) hook(t *testing.T, method, path string, body any) (int, string) {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequestWithContext(t.Context(), method, path, bytes.NewReader(raw))
	rec := httptest.NewRecorder()
	r.h.Hooks().ServeHTTP(rec, req)
	return rec.Code, rec.Body.String()
}

var harnessCalls = []struct{ method, path string }{
	{http.MethodPost, "/install"},
	{http.MethodPost, "/start"},
	{http.MethodPost, "/list"},
	{http.MethodPost, "/call"},
	{http.MethodGet, "/observations"},
	{http.MethodGet, "/nothing"},
}

func TestEveryCallBeforeRunAnswers503AndNothingIsInstalledOrStarted(t *testing.T) {
	inst := &fakeInstaller{out: Installed{Command: []string{"/bin/true"}}}
	run := newIdleRun(t, inst)
	for _, auth := range []string{"", "Bearer ", "Bearer " + testToken} {
		for _, c := range harnessCalls {
			status, body := run.doAs(t, auth, c.method, c.path, installBody("go", "example.com/x@v1.0.0"))
			if status != http.StatusServiceUnavailable {
				t.Errorf("%s %s with %q before /run = %d, want 503", c.method, c.path, auth, status)
			}
			if _, ok := body["observations"]; ok {
				t.Errorf("%s %s before /run gave out observations", c.method, c.path)
			}
		}
	}
	if len(inst.got) != 0 || run.h.run != nil || run.h.srv != nil {
		t.Errorf("a call before /run installed %v or started a server", inst.got)
	}
}

func TestReadyAnswers503UntilTheAPIListens(t *testing.T) {
	run := newIdleRun(t, &fakeInstaller{})
	if status, _ := run.hook(t, http.MethodPost, HooksPrefix+"ready", nil); status != http.StatusServiceUnavailable {
		t.Errorf("/ready before the API listens = %d, want 503", status)
	}
	run.h.Listening()
	if status, _ := run.hook(t, http.MethodPost, HooksPrefix+"ready", nil); status != http.StatusOK {
		t.Errorf("/ready once the API listens = %d, want 200", status)
	}
	if status, _ := run.hook(t, http.MethodGet, HooksPrefix+"ready", nil); status != http.StatusNotFound {
		t.Errorf("GET /ready = %d, want 404", status)
	}
	if obs := run.h.obs.all(); len(obs) != 0 {
		t.Errorf("hooks before the run were observed: %v", obs)
	}
}

func TestRunDeliversTheTokenTheAPIThenNeedsAndASecondRunIsRefused(t *testing.T) {
	run := newIdleRun(t, &fakeInstaller{})
	if status, body := run.hook(t, http.MethodPost, HooksPrefix+"run", runHookRequest(t, testToken, testCanaries)); status != http.StatusOK {
		t.Fatalf("POST /run = %d %s", status, body)
	}
	for _, c := range harnessCalls {
		if status, _ := run.doAs(t, "Bearer wrong", c.method, c.path, nil); status != http.StatusUnauthorized {
			t.Errorf("%s %s with another token = %d, want 401", c.method, c.path, status)
		}
	}
	if status, _ := run.do(t, http.MethodGet, "/observations", nil); status != http.StatusOK {
		t.Errorf("GET /observations with the run's token = %d, want 200", status)
	}

	status, _ := run.hook(t, http.MethodPost, HooksPrefix+"run", runHookRequest(t, "attacker-token", testCanaries))
	if status != http.StatusConflict {
		t.Errorf("a second /run = %d, want 409", status)
	}
	if status, _ := run.doAs(t, "Bearer attacker-token", http.MethodGet, "/observations", nil); status != http.StatusUnauthorized {
		t.Errorf("the second /run's token = %d, want 401", status)
	}
	status, body := run.do(t, http.MethodGet, "/observations", nil)
	obs := observations(t, body)
	if status != http.StatusOK || len(obs) != 1 || obs[0].Kind != ObservedHook {
		t.Fatalf("observations = %d %+v, want the second /run", status, obs)
	}
	var d HookDetail
	if err := json.Unmarshal(obs[0].Detail, &d); err != nil {
		t.Fatal(err)
	}
	if d.Path != HooksPrefix+"run" || d.Status != http.StatusConflict {
		t.Errorf("detail = %+v", d)
	}
}

func TestRunRefusesABadPayloadAndTheRunDoesNotStart(t *testing.T) {
	body := func(payload string) map[string]any {
		return map[string]any{"microvmId": "mvm-1", "runHookPayload": payload}
	}
	encode := func(v any) string {
		raw, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return string(raw)
	}
	multiline := append(append([]Canary{}, testCanaries[:5]...), Canary{CanaryPassword, "test\npassword"})
	for name, b := range map[string]any{
		"no payload":              body(""),
		"a payload not JSON":      body("token=x"),
		"no token":                runHookRequest(t, "", testCanaries),
		"a missing canary":        runHookRequest(t, testToken, testCanaries[1:]),
		"an unknown canary":       runHookRequest(t, testToken, append([]Canary{{"slack-token", "xoxb-1"}}, testCanaries...)),
		"a password on two lines": runHookRequest(t, testToken, multiline),
		"an unknown field":        body(encode(map[string]any{"token": testToken, "canaries": testCanaries, "allowHosts": []string{"x"}})),
		"a payload over 16 KB":    body(encode(map[string]any{"token": strings.Repeat("t", maxRunHookPayload), "canaries": testCanaries})),
		"a body not JSON":         "runHookPayload",
	} {
		run := newIdleRun(t, &fakeInstaller{})
		if status, resp := run.hook(t, http.MethodPost, HooksPrefix+"run", b); status != http.StatusBadRequest {
			t.Errorf("%s: /run = %d %s, want 400", name, status, resp)
		}
		if status, _ := run.do(t, http.MethodGet, "/observations", nil); status != http.StatusServiceUnavailable {
			t.Errorf("%s: the API answers %d after a refused /run, want 503", name, status)
		}
		if files := filesUnder(t, run.home); len(files) != 0 {
			t.Errorf("%s: a refused /run wrote %v", name, files)
		}
	}
}

func TestTheHomeIsPlantedOnlyAfterRun(t *testing.T) {
	run := newIdleRun(t, &fakeInstaller{})
	run.h.Listening()
	if status, _ := run.hook(t, http.MethodPost, HooksPrefix+"ready", nil); status != http.StatusOK {
		t.Fatalf("/ready = %d", status)
	}
	// Here Lambda snapshots the image: nothing of a run is on disk.
	if files := filesUnder(t, run.home); len(files) != 0 {
		t.Fatalf("the home holds %v before /run", files)
	}

	if status, body := run.hook(t, http.MethodPost, HooksPrefix+"run", runHookRequest(t, testToken, testCanaries)); status != http.StatusOK {
		t.Fatalf("POST /run = %d %s", status, body)
	}
	for file, wants := range map[string][]string{
		".ssh/id_ed25519":  {testCanaries[3].Value},
		".aws/credentials": {"aws_access_key_id = " + testCanaries[1].Value, "aws_secret_access_key = " + testCanaries[2].Value},
		".npmrc":           {"_authToken=" + testCanaries[0].Value},
		".gitconfig":       {"email = " + testCanaries[4].Value},
		".bash_history":    {"GITHUB_TOKEN=" + testCanaries[0].Value, testCanaries[5].Value},
	} {
		raw, err := os.ReadFile(filepath.Join(run.home, file))
		if err != nil {
			t.Errorf("the home lacks %s after /run: %v", file, err)
			continue
		}
		for _, w := range wants {
			if !strings.Contains(string(raw), w) {
				t.Errorf("%s lacks %q:\n%s", file, w, raw)
			}
		}
	}
	info, err := os.Stat(filepath.Join(run.home, ".ssh", "id_ed25519"))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Errorf("~/.ssh/id_ed25519 is %v, %v; want 0600", info, err)
	}
	for _, f := range filesUnder(t, run.home) {
		raw, err := os.ReadFile(filepath.Join(run.home, f))
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(raw), testToken) {
			t.Errorf("%s holds the run's token", f)
		}
	}
	if obs := run.h.obs.all(); len(obs) != 0 {
		t.Errorf("planting the home was observed: %v", obs)
	}
}

// filesUnder lists the files under dir, relative to it.
func filesUnder(t *testing.T, dir string) []string {
	t.Helper()
	var files []string
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			rel, err := filepath.Rel(dir, path)
			if err != nil {
				return err
			}
			files = append(files, rel)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return files
}

func TestTwoRacingRunsStartTheRunOnceAndTheLoserIsObserved(t *testing.T) {
	run := newIdleRun(t, &fakeInstaller{})
	statuses := make(chan int, 2)
	for _, token := range []string{testToken, "attacker-token"} {
		body := runHookRequest(t, token, testCanaries)
		go func() {
			raw, _ := json.Marshal(body)
			req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, HooksPrefix+"run", bytes.NewReader(raw))
			rec := httptest.NewRecorder()
			run.h.Hooks().ServeHTTP(rec, req)
			statuses <- rec.Code
		}()
	}
	got := []int{<-statuses, <-statuses}
	if !slices.Contains(got, http.StatusOK) || !slices.Contains(got, http.StatusConflict) {
		t.Fatalf("two racing /runs = %v, want one 200 and one 409", got)
	}
	obs := run.h.obs.all()
	if len(obs) != 1 || obs[0].Kind != ObservedHook {
		t.Errorf("observations = %+v, want the refused /run", obs)
	}
}
