package harness

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeTimeIn is a fake clock whose offset file is in dir. The library
// isn't loaded by any test, so it needn't exist.
func fakeTimeIn(dir string) FakeTime {
	return FakeTime{Lib: "/usr/local/lib/faketime/libfaketime.so.1", File: filepath.Join(dir, "faketime")}
}

func readClock(t *testing.T, ft FakeTime) string {
	t.Helper()
	raw, err := os.ReadFile(ft.File)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func TestClockMovesTheServersClockForwardAndAnswersTheClockInForce(t *testing.T) {
	ft := fakeTimeIn(t.TempDir())
	run := newTestRunWith(t, func(c *Config) { c.FakeTime = ft })
	if got := readClock(t, ft); got != "+0\n" {
		t.Errorf("the clock before any move is %q, want +0", got)
	}
	for _, step := range []struct {
		offset, total, file string
		days                int
	}{
		{"720h", "720h0m0s", "+2592000\n", 30},
		{"24h", "744h0m0s", "+2678400\n", 31},
	} {
		status, body := run.do(t, http.MethodPost, "/clock", map[string]any{"offset": step.offset})
		if status != http.StatusOK {
			t.Fatalf("POST /clock %s = %d %v", step.offset, status, body)
		}
		var offset string
		_ = json.Unmarshal(body["offset"], &offset)
		want := mustJSON(t, testNow.AddDate(0, 0, step.days))
		if offset != step.total || !jsonEqual(t, body["now"], want) {
			t.Errorf("POST /clock %s = offset %s, now %s; want %s and %s", step.offset, body["offset"], body["now"], step.total, want)
		}
		if got := readClock(t, ft); got != step.file {
			t.Errorf("after %s the clock file holds %q, want %q", step.offset, got, step.file)
		}
	}
}

func TestClockRefusesWhatIsNotAForwardMoveWithinItsBounds(t *testing.T) {
	ft := fakeTimeIn(t.TempDir())
	run := newTestRunWith(t, func(c *Config) { c.FakeTime = ft })
	for _, bad := range []string{"", "soon", "-1h", "0s", "9000h"} {
		if status, _ := run.do(t, http.MethodPost, "/clock", map[string]any{"offset": bad}); status != http.StatusBadRequest {
			t.Errorf("POST /clock %q = %d, want 400", bad, status)
		}
	}
	for range 10 {
		run.do(t, http.MethodPost, "/clock", map[string]any{"offset": "8000h"})
	}
	if status, _ := run.do(t, http.MethodPost, "/clock", map[string]any{"offset": "8000h"}); status != http.StatusBadRequest {
		t.Errorf("POST /clock past the total bound = %d, want 400", status)
	}
	if got := readClock(t, ft); strings.HasPrefix(got, "-") {
		t.Errorf("the clock file holds %q", got)
	}
}

func TestClockWithoutAFakeClockIsAConflict(t *testing.T) {
	run := newTestRun(t, &fakeInstaller{})
	if status, _ := run.do(t, http.MethodPost, "/clock", map[string]any{"offset": "720h"}); status != http.StatusConflict {
		t.Errorf("POST /clock = %d, want 409", status)
	}
}

func TestTheServerRunsWithTheFakeClockPreloaded(t *testing.T) {
	ft := fakeTimeIn(t.TempDir())
	run := newTestRunWith(t, func(c *Config) { c.FakeTime = ft })
	startTestServerIn(t, run)
	if status, body := run.do(t, http.MethodPost, "/start", map[string]any{}); status != http.StatusOK {
		t.Fatalf("POST /start = %d %v", status, body)
	}
	env := strings.Split(toolText(t, call(t, run, "env", nil)), "\n")
	for name, want := range map[string]string{
		"LD_PRELOAD":                   ft.Lib,
		"FAKETIME_TIMESTAMP_FILE":      ft.File,
		"FAKETIME_NO_CACHE":            "1",
		"FAKETIME_DONT_FAKE_MONOTONIC": "1",
	} {
		if got := envValue(env, name); got != want {
			t.Errorf("the server's %s = %q, want %q", name, got, want)
		}
	}
}
