package harness

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// installedPackage installs, with a fake, an npm package whose directory
// holds a source file, a large one, links in and out of it and a FIFO.
func installedPackage(t *testing.T) testRun {
	t.Helper()
	inst := &fakeInstaller{}
	run := newTestRun(t, inst)
	pkg := filepath.Join(run.workdir, "node_modules", "weather")
	inst.out = Installed{Resolved: []byte("{}"), Command: []string{"weather"}, Source: pkg}
	inst.write = func(Sandbox) {
		must(t, os.MkdirAll(filepath.Join(pkg, "dist"), 0o750))
		must(t, os.WriteFile(filepath.Join(pkg, "dist", "index.js"), []byte("fetch('https://api.open-meteo.com')\n"), 0o600))
		must(t, os.WriteFile(filepath.Join(pkg, "big.js"), []byte(strings.Repeat("x", maxSource+10)), 0o600))
		must(t, os.WriteFile(filepath.Join(run.workdir, "secret.txt"), []byte("outside the package"), 0o600))
		must(t, os.Symlink("dist/index.js", filepath.Join(pkg, "link-in.js")))
		must(t, os.Symlink("../../secret.txt", filepath.Join(pkg, "link-out.js")))
		must(t, os.Symlink("/etc/passwd", filepath.Join(pkg, "link-abs.js")))
		must(t, syscall.Mkfifo(filepath.Join(pkg, "fifo.js"), 0o600))
		must(t, os.Link(filepath.Join(run.workdir, "secret.txt"), filepath.Join(pkg, "hard.js")))
	}
	if status, body := run.do(t, http.MethodPost, "/install", installBody("npm", "weather@1.0.0")); status != http.StatusOK {
		t.Fatalf("POST /install = %d %v", status, body)
	}
	return run
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func TestSourceAnswersAFileOfTheInstalledPackage(t *testing.T) {
	run := installedPackage(t)
	for _, p := range []string{"dist/index.js", "link-in.js"} {
		status, body := run.do(t, http.MethodPost, "/source", map[string]any{"path": p})
		if status != http.StatusOK || !strings.Contains(text(t, body["content"]), "api.open-meteo.com") || text(t, body["path"]) != p {
			t.Errorf("POST /source %s = %d %v, want its content", p, status, body)
		}
	}
}

func TestSourceIsBoundedTo64KB(t *testing.T) {
	run := installedPackage(t)
	status, body := run.do(t, http.MethodPost, "/source", map[string]any{"path": "big.js"})
	if status != http.StatusOK || len(text(t, body["content"])) != maxSource || !jsonEqual(t, body["truncated"], json.RawMessage(`true`)) {
		t.Errorf("POST /source big.js = %d, %d bytes, truncated %s; want %d bytes, truncated", status, len(text(t, body["content"])), body["truncated"], maxSource)
	}
}

func TestSourceRefusesAPathOrALinkOutOfThePackage(t *testing.T) {
	run := installedPackage(t)
	for _, p := range []string{"../../secret.txt", "dist/../../../secret.txt", "/etc/passwd", "", "link-out.js", "link-abs.js", "fifo.js", "dist", "hard.js"} {
		if status, body := run.do(t, http.MethodPost, "/source", map[string]any{"path": p}); status != http.StatusBadRequest {
			t.Errorf("POST /source %q = %d %v, want 400", p, status, body)
		}
	}
	if status, _ := run.do(t, http.MethodPost, "/source", map[string]any{"path": "missing.js"}); status != http.StatusNotFound {
		t.Errorf("POST /source missing.js = %d, want 404", status)
	}
}

func TestSourceRefusesAPackageDirectorySwappedForALink(t *testing.T) {
	// The relative link stays inside the home, so os.Root alone follows it;
	// only the check of the opened directory's real path refuses it.
	for _, target := range []string{"../..", "/"} {
		run := installedPackage(t)
		pkg := filepath.Join(run.workdir, "node_modules", "weather")
		must(t, os.Rename(pkg, pkg+".moved"))
		must(t, os.Symlink(target, pkg))
		if status, body := run.do(t, http.MethodPost, "/source", map[string]any{"path": "secret.txt"}); status != http.StatusBadRequest {
			t.Errorf("POST /source through a link to %s = %d %v, want 400", target, status, body)
		}
	}
}

func TestSourceBeforeAnInstallIsAConflict(t *testing.T) {
	run := newTestRun(t, &fakeInstaller{})
	if status, _ := run.do(t, http.MethodPost, "/source", map[string]any{"path": "dist/index.js"}); status != http.StatusConflict {
		t.Errorf("POST /source = %d, want 409", status)
	}
}

func TestAFileTheAccountDoesNotOwnIsNotOpened(t *testing.T) {
	dir := t.TempDir()
	must(t, os.WriteFile(filepath.Join(dir, "f"), []byte("x"), 0o600))
	root, err := os.OpenRoot(dir)
	must(t, err)
	defer func() { _ = root.Close() }()
	if os.Getuid() == 4242 {
		t.Skip("the test runs as the stranger's uid")
	}
	stranger := Account{Switch: true, UID: 4242}
	if f, _, err := stranger.openOwned(root, "f", true); err == nil {
		_ = f.Close()
		t.Error("a file of another user was opened")
	}
}

func TestAFileSwappedBetweenTheLookAndTheOpenIsRefused(t *testing.T) {
	dir := t.TempDir()
	must(t, os.WriteFile(filepath.Join(dir, "x"), []byte("written"), 0o600))
	must(t, os.WriteFile(filepath.Join(dir, "other"), []byte("never written"), 0o600))
	root, err := os.OpenRoot(dir)
	must(t, err)
	defer func() { _ = root.Close() }()
	afterLook = func(string) { must(t, os.Rename(filepath.Join(dir, "other"), filepath.Join(dir, "x"))) }
	t.Cleanup(func() { afterLook = nil })
	if f, _, err := (Account{}).openOwned(root, "x", false); err == nil {
		_ = f.Close()
		t.Error("the file swapped in after the look was opened")
	}
}
