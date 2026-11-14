package harness

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha1" //nolint:gosec // npm's packument carries a SHA-1 shasum beside the integrity
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// realSandbox runs commands for real, as the test's own user, in a fresh
// working directory, found on the test's PATH, with extra in the
// environment.
func realSandbox(t *testing.T, extra ...string) Sandbox {
	t.Helper()
	home := t.TempDir()
	w := filepath.Join(home, "work")
	if err := os.Mkdir(w, 0o700); err != nil {
		t.Fatal(err)
	}
	a := Account{Name: "dev", Home: home}
	env := a.env(os.Getenv("PATH"), append([]string{"TMPDIR=" + home}, extra...)...)
	return Sandbox{Workdir: w, Env: env, Run: func(ctx context.Context, args []string, out io.Writer) error {
		return a.run(ctx, w, env, args, out)
	}}
}

// wheel writes a pure-Python wheel of name and version, with files and
// dependencies, into dir, and answers its SHA-256.
func wheel(t *testing.T, dir, name, version string, files map[string]string, requires ...string) string {
	t.Helper()
	info := name + "-" + version + ".dist-info/"
	all := map[string]string{
		info + "METADATA": "Metadata-Version: 2.1\nName: " + name + "\nVersion: " + version + "\n" +
			strings.Join(append(prefixed("Requires-Dist: ", requires), ""), "\n"),
		info + "WHEEL": "Wheel-Version: 1.0\nGenerator: test\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
	}
	for k, v := range files {
		all[k] = v
	}
	var buf bytes.Buffer
	z := zip.NewWriter(&buf)
	var record strings.Builder
	for k, v := range all {
		f, err := z.Create(k)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.WriteString(f, v); err != nil {
			t.Fatal(err)
		}
		record.WriteString(k + ",,\n")
	}
	f, err := z.Create(info + "RECORD")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(f, record.String()+info+"RECORD,,\n"); err != nil {
		t.Fatal(err)
	}
	if err := z.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name+"-"+version+"-py3-none-any.whl"), buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(buf.Bytes())
	return hex.EncodeToString(sum[:])
}

func prefixed(prefix string, lines []string) []string {
	out := make([]string, len(lines))
	for i, l := range lines {
		out[i] = prefix + l
	}
	return out
}

// TestThePyPISetIsTheResolversNotWhatTheWheelSaysOfItself installs the
// reviewer's evilmeta: a plain wheel whose .data/purelib directory plants
// .dist-info files, so the installed venv lists a FORGED package, a forged
// version of its real dependency, and evilmeta renamed to an approved one.
func TestThePyPISetIsTheResolversNotWhatTheWheelSaysOfItself(t *testing.T) {
	if err := exec.Command("python3", "-c", "import ensurepip, venv").Run(); err != nil {
		t.Skipf("no python3 with venv and ensurepip here: %v", err)
	}
	index := t.TempDir()
	tiny := wheel(t, index, "tinydep", "1.0.0", map[string]string{"tinydep/__init__.py": ""})
	purelib := "evilmeta-1.0.0.data/purelib/"
	evil := wheel(t, index, "evilmeta", "1.0.0", map[string]string{
		"evilmeta/__init__.py":                              "def main():\n    pass\n",
		purelib + "FORGED-9.9.9.dist-info/METADATA":         "Metadata-Version: 2.1\nName: FORGED\nVersion: 9.9.9\n",
		purelib + "tinydep-0.0.1+forged.dist-info/METADATA": "Metadata-Version: 2.1\nName: tinydep\nVersion: 0.0.1+forged\n",
		purelib + "goodpkg-3.1.4.dist-info/METADATA":        "Metadata-Version: 2.1\nName: goodpkg\nVersion: 3.1.4\n",
	}, "tinydep==1.0.0")
	sb := realSandbox(t, "PIP_NO_INDEX=1", "PIP_FIND_LINKS="+index)
	got, err := Toolchain{}.Install(t.Context(), Package{EcosystemPyPI, "evilmeta", "1.0.0"}, sb)
	if err != nil {
		t.Fatalf("install: %v\n%s", err, got.Log)
	}
	want := "evilmeta==1.0.0 --hash=sha256:" + evil + "\ntinydep==1.0.0 --hash=sha256:" + tiny + "\n"
	if string(got.Resolved) != want {
		t.Errorf("resolved %q, want the resolver's set %q", got.Resolved, want)
	}
	// The forgery is real: the venv now says what evilmeta wrote.
	var listing bytes.Buffer
	listing.Write(mustList(t, sb))
	for _, forged := range []string{"FORGED==9.9.9", "goodpkg==3.1.4", "tinydep==0.0.1+forged"} {
		if !strings.Contains(listing.String(), forged) {
			t.Errorf("the venv lists %q, without the planted %s: the test plants nothing", listing.String(), forged)
		}
		if !strings.Contains(got.Log, "claims "+forged) {
			t.Errorf("the log does not note the claim %s:\n%s", forged, got.Log)
		}
	}
}

func mustList(t *testing.T, sb Sandbox) []byte {
	t.Helper()
	out, err := listVenv(t.Context(), sb, filepath.Join(sb.Workdir, "venv"))
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// npmTarball is an npm package's tarball: package.json and index.js under
// package/.
func npmTarball(t *testing.T, manifest string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for name, body := range map[string]string{"package/package.json": manifest, "package/index.js": "#!/usr/bin/env node\n"} {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(body))}); err != nil {
			t.Fatal(err)
		}
		if _, err := io.WriteString(tw, body); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// npmRegistry serves packages, each a manifest, at one version, 1.0.0.
func npmRegistry(t *testing.T, manifests map[string]map[string]any) *httptest.Server {
	t.Helper()
	tarballs := map[string][]byte{}
	packuments := map[string][]byte{}
	// Unstarted, so the maps are filled before any request reads them.
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if b, ok := tarballs[r.URL.Path]; ok {
			_, _ = w.Write(b)
			return
		}
		if b, ok := packuments[r.URL.Path]; ok {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(b)
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(srv.Close)
	base := "http://" + srv.Listener.Addr().String()
	for name, manifest := range manifests {
		manifest["name"], manifest["version"] = name, "1.0.0"
		raw, err := json.Marshal(manifest)
		if err != nil {
			t.Fatal(err)
		}
		tgz := npmTarball(t, string(raw))
		path := "/" + name + "/-/" + name + "-1.0.0.tgz"
		tarballs[path] = tgz
		sha512sum, sha1sum := sha512.Sum512(tgz), sha1.Sum(tgz) //nolint:gosec // the packument's shasum field is SHA-1
		manifest["dist"] = map[string]string{
			"tarball":   base + path,
			"integrity": "sha512-" + base64.StdEncoding.EncodeToString(sha512sum[:]),
			"shasum":    hex.EncodeToString(sha1sum[:]),
		}
		packument, err := json.Marshal(map[string]any{
			"name":      name,
			"dist-tags": map[string]string{"latest": "1.0.0"},
			"versions":  map[string]any{"1.0.0": manifest},
		})
		if err != nil {
			t.Fatal(err)
		}
		packuments["/"+name] = packument
	}
	srv.Start()
	return srv
}

// TestTheNPMSetIsReadBeforeAnInstallScriptCanRewriteIt installs a package
// whose postinstall script forks a process that rewrites package-lock.json.
func TestTheNPMSetIsReadBeforeAnInstallScriptCanRewriteIt(t *testing.T) {
	if _, err := exec.LookPath("npm"); err != nil {
		t.Skip("no npm here")
	}
	const forge = `(echo '{"forged":true}' > "$INIT_CWD/package-lock.json") & wait`
	srv := npmRegistry(t, map[string]map[string]any{
		"evilnpm": {
			"bin":          map[string]string{"evilnpm": "index.js"},
			"dependencies": map[string]string{"tinynpm": "1.0.0"},
			"scripts":      map[string]string{"postinstall": forge},
		},
		"tinynpm": {},
	})
	sb := realSandbox(t, "npm_config_registry="+srv.URL+"/", "npm_config_cache="+filepath.Join(t.TempDir(), "npm"),
		"npm_config_update_notifier=false")
	got, err := Toolchain{}.Install(t.Context(), Package{EcosystemNPM, "evilnpm", "1.0.0"}, sb)
	if err != nil {
		t.Fatalf("install: %v\n%s", err, got.Log)
	}
	var lock struct {
		Packages map[string]struct {
			Version   string `json:"version"`
			Integrity string `json:"integrity"`
		} `json:"packages"`
	}
	if err := json.Unmarshal(got.Resolved, &lock); err != nil {
		t.Fatalf("resolved %q is not the lockfile: %v", got.Resolved, err)
	}
	for _, dep := range []string{"node_modules/evilnpm", "node_modules/tinynpm"} {
		if p := lock.Packages[dep]; p.Version != "1.0.0" || !strings.HasPrefix(p.Integrity, "sha512-") {
			t.Errorf("the reported lockfile has %s as %+v, want 1.0.0 with its integrity", dep, p)
		}
	}
	// The script did run, and did rewrite the lockfile on disk.
	onDisk, err := os.ReadFile(filepath.Join(sb.Workdir, "package-lock.json"))
	if err != nil || !strings.Contains(string(onDisk), "forged") {
		t.Errorf("the lockfile on disk is %q, %v: the install script did not run", onDisk, err)
	}
	if want := filepath.Join(sb.Workdir, "node_modules", ".bin", "evilnpm"); len(got.Command) != 1 || got.Command[0] != want {
		t.Errorf("command %q, want %s", got.Command, want)
	}
}

// TestKillAllEndsEveryProcessOfTheAccount needs root, to switch users.
func TestKillAllEndsEveryProcessOfTheAccount(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("switching to the account needs root")
	}
	if _, err := os.Stat(setpriv); err != nil {
		t.Skipf("no %s here", setpriv)
	}
	// A uid no one else on this machine uses.
	a := Account{Name: "dev", Home: "/", UID: 61234, GID: 61234, Switch: true}
	// A process of the account in a session of its own, outside any
	// process group the harness knows: a lingering install script.
	lingering := a.command(t.Context(), "/", a.env("/usr/bin:/bin"), []string{"/usr/bin/setsid", "/bin/sleep", "600"})
	lingering.SysProcAttr.Setpgid = false
	if err := lingering.Start(); err != nil {
		t.Fatal(err)
	}
	if err := a.killAll(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := lingering.Wait(); err == nil || !strings.Contains(err.Error(), "killed") {
		t.Errorf("the lingering process ended with %v, want killed", err)
	}
	if err := a.killAll(t.Context()); err != nil {
		t.Errorf("with nothing left to kill: %v", err)
	}
}
