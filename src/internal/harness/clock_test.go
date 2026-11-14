package harness

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
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
	for _, bad := range []string{"", "soon", "-1h", "0s", "9000h", "1.5s"} {
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

func TestClockSaysWhetherTheServersRuntimeSeesTheMove(t *testing.T) {
	ft := fakeTimeIn(t.TempDir())
	run := newTestRunWith(t, func(c *Config) { c.FakeTime = ft })
	_, body := run.do(t, http.MethodPost, "/clock", map[string]any{"offset": "1h"})
	if got := text(t, body["applies"]); got != appliesUnknown {
		t.Errorf("before an install, applies = %q, want unknown", got)
	}
	// The test server is this test binary: Go, which libfaketime can't fake.
	startTestServerIn(t, run)
	if status, body := run.do(t, http.MethodPost, "/start", map[string]any{}); status != http.StatusOK {
		t.Fatalf("POST /start = %d %v", status, body)
	}
	_, body = run.do(t, http.MethodPost, "/clock", map[string]any{"offset": "1h"})
	if got := text(t, body["applies"]); got != appliesNo || !strings.Contains(text(t, body["why"]), "Go") {
		t.Errorf("for a Go server, applies = %q (%s), want no", got, body["why"])
	}
}

func TestFakeTimeAppliesToADynamicBinaryAndTheScriptsItRuns(t *testing.T) {
	const path = "/usr/local/bin:/usr/bin:/bin"
	found, ok := (Account{}).interpreter("sh", path)
	if !ok {
		t.Skip("no sh")
	}
	sh := []string{found}
	if applies, why := (Account{}).fakeTimeApplies(sh, ""); applies != appliesYes {
		t.Skipf("sh here is %s (%s); the test needs a dynamic one", applies, why)
	}
	dir := t.TempDir()
	for name, script := range map[string]string{
		"direct": "#!" + sh[0] + "\necho hi\n",
		"env":    "#!/usr/bin/env sh\necho hi\n",
	} {
		file := filepath.Join(dir, name)
		must(t, os.WriteFile(file, []byte(script), 0o755)) //nolint:gosec // a script anyone may read, as an installed one is
		if applies, why := (Account{}).fakeTimeApplies([]string{file}, path); applies != appliesYes {
			t.Errorf("%s script: applies = %s (%s), want yes", name, applies, why)
		}
	}
	missing := filepath.Join(dir, "missing")
	must(t, os.WriteFile(missing, []byte("#!/usr/bin/env no-such-interpreter\n"), 0o755)) //nolint:gosec // a script anyone may read, as an installed one is
	if applies, _ := (Account{}).fakeTimeApplies([]string{missing}, path); applies != appliesUnknown {
		t.Errorf("a script with no interpreter: applies = %s, want unknown", applies)
	}
	exe, err := os.Executable()
	must(t, err)
	if applies, _ := (Account{}).fakeTimeApplies([]string{exe}, ""); applies != appliesNo {
		t.Errorf("a Go binary: applies = %s, want no", applies)
	}
}

func TestFakeTimeAppliesReadsNothingTheAccountCouldNotAndEchoesNothingOfIt(t *testing.T) {
	dir := t.TempDir()
	secret := filepath.Join(dir, "secret")
	must(t, os.WriteFile(secret, []byte("#!/opt/TOPSECRET-TOKEN-abc123 --x\n"), 0o600))
	// What an install script can do to the command the server starts.
	bin := filepath.Join(dir, "weather")
	must(t, os.Symlink(secret, bin))
	stranger := Account{UID: 4242}
	if os.Getuid() == 4242 {
		t.Skip("the test runs as the stranger's uid")
	}
	opened := watchOpens(t, secret)
	applies, why := stranger.fakeTimeApplies([]string{bin}, "")
	if applies != appliesUnknown || strings.Contains(why, "TOPSECRET") {
		t.Errorf("a link to a file the account can't read: %s (%s), want unknown, naming nothing in the file", applies, why)
	}
	if opened() {
		t.Error("the harness opened a file the account can't read; it must look first, so no device is ever opened")
	}
	for _, target := range []string{"/dev/zero", filepath.Join(dir, "missing")} {
		link := filepath.Join(dir, filepath.Base(target)+"-link")
		must(t, os.Symlink(target, link))
		if applies, why := stranger.fakeTimeApplies([]string{link}, ""); applies != appliesUnknown || why != filepath.Base(link)+" can't be read as the account" {
			t.Errorf("a link to %s: %s (%s), want the same unknown as any unreadable file", target, applies, why)
		}
	}
}

func TestFakeTimeDoesNotApplyToAStaticBinary(t *testing.T) {
	exe := filepath.Join(t.TempDir(), "static")
	must(t, os.WriteFile(exe, staticELF(), 0o755)) //nolint:gosec // an executable anyone may read, as an installed one is
	if applies, why := (Account{}).fakeTimeApplies([]string{exe}, ""); applies != appliesNo || !strings.Contains(why, "statically linked") {
		t.Errorf("a static binary: %s (%s), want no", applies, why)
	}
}

// staticELF is the smallest static ELF executable: a 64-bit header and one
// loadable segment, with no interpreter and no Go build information.
func staticELF() []byte {
	const ehsize, phsize = 64, 56
	var b bytes.Buffer
	b.Write([]byte{0x7f, 'E', 'L', 'F', 2, 1, 1, 0})
	b.Write(make([]byte, 8))
	le := binary.LittleEndian
	for _, v := range []any{
		uint16(elf.ET_EXEC), uint16(elf.EM_X86_64), uint32(1),
		uint64(0x400000 + ehsize + phsize), uint64(ehsize), uint64(0),
		uint32(0), uint16(ehsize), uint16(phsize), uint16(1), uint16(0), uint16(0), uint16(0),
		// The one program header: PT_LOAD, readable and executable.
		uint32(elf.PT_LOAD), uint32(elf.PF_R | elf.PF_X), uint64(0), uint64(0x400000), uint64(0x400000),
		uint64(ehsize + phsize + 1), uint64(ehsize + phsize + 1), uint64(0x1000),
	} {
		_ = binary.Write(&b, le, v)
	}
	b.WriteByte(0xf4) // hlt
	return b.Bytes()
}

// watchOpens says, when called, whether file was opened since watchOpens.
func watchOpens(t *testing.T, file string) func() bool {
	t.Helper()
	fd, err := syscall.InotifyInit1(syscall.IN_NONBLOCK | syscall.IN_CLOEXEC)
	must(t, err)
	t.Cleanup(func() { _ = syscall.Close(fd) })
	if _, err := syscall.InotifyAddWatch(fd, file, syscall.IN_OPEN); err != nil {
		t.Fatal(err)
	}
	return func() bool {
		buf := make([]byte, 4096)
		n, err := syscall.Read(fd, buf)
		return err == nil && n > 0
	}
}
