package harness

import (
	"bytes"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestAccountCommandsRunAsTheUnprivilegedUser(t *testing.T) {
	a := Account{Name: "dev", Home: "/home/dev", UID: 1000, GID: 1001, Switch: true}
	cmd := a.command(t.Context(), "/home/dev/projects/server", a.env("/usr/bin"), []string{"/usr/bin/true"})
	cred := cmd.SysProcAttr.Credential
	if cred == nil || cred.Uid != 1000 || cred.Gid != 1001 || len(cred.Groups) != 0 {
		t.Errorf("credential = %+v, want uid 1000, gid 1001 and no other groups", cred)
	}
	if !cmd.SysProcAttr.Setpgid {
		t.Error("the command is not its own process group, so it can't be killed whole")
	}
	if want := []string{"/usr/bin/setpriv", "--no-new-privs", "--", "/usr/bin/true"}; cmd.Path != want[0] || !slices.Equal(cmd.Args, want) {
		t.Errorf("command = %s %q, want %q: the server starts with no_new_privs", cmd.Path, cmd.Args, want)
	}
	if cmd.Dir != "/home/dev/projects/server" {
		t.Errorf("dir = %s", cmd.Dir)
	}
	want := []string{
		"HOME=/home/dev", "USER=dev", "LOGNAME=dev", "SHELL=/bin/bash",
		"LANG=en_US.UTF-8", "TERM=xterm-256color", "PATH=/usr/bin",
	}
	if !slices.Equal(cmd.Env, want) {
		t.Errorf("env = %q, want exactly %q", cmd.Env, want)
	}
}

func TestAccountWithoutSwitchRunsAsTheHarnessUser(t *testing.T) {
	a := Account{Name: "dev", Home: t.TempDir()}
	if cred := a.sysProcAttr().Credential; cred != nil {
		t.Errorf("credential = %+v, want none", cred)
	}
	if cmd := a.command(t.Context(), a.Home, nil, []string{"/usr/bin/true"}); !slices.Equal(cmd.Args, []string{"/usr/bin/true"}) {
		t.Errorf("command = %q, want it unwrapped", cmd.Args)
	}
}

func TestResolveFindsTheHarnesssCommandsOnTheTrustedPathOnly(t *testing.T) {
	trusted, planted := t.TempDir(), t.TempDir()
	for _, dir := range []string{trusted, planted} {
		if err := os.WriteFile(filepath.Join(dir, "cat"), []byte("#!/bin/sh\n"), 0o755); err != nil { //nolint:gosec // an executable test script
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(trusted, "notes"), []byte("not a command\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct {
		args []string
		path string
		want []string
	}{
		"a bare name":            {[]string{"cat", "--", "f"}, "relative/bin:" + trusted, []string{filepath.Join(trusted, "cat"), "--", "f"}},
		"a name with a slash":    {[]string{"./cat"}, trusted, []string{"./cat"}},
		"an absolute path":       {[]string{"/usr/bin/true"}, trusted, []string{"/usr/bin/true"}},
		"a file not executable":  {[]string{"notes"}, trusted, nil},
		"not on the trusted one": {[]string{"go"}, trusted, nil},
	} {
		got, err := resolve(tc.args, tc.path)
		if tc.want == nil {
			if err == nil {
				t.Errorf("%s: resolve = %q, want an error", name, got)
			}
			continue
		}
		if err != nil || !slices.Equal(got, tc.want) {
			t.Errorf("%s: resolve = %q, %v; want %q", name, got, err, tc.want)
		}
	}
}

func TestTheInstallsOwnCommandsIgnoreCommandsThePackagePlants(t *testing.T) {
	run := newTestRun(t, &fakeInstaller{})
	sb := run.h.sandbox()
	planted := []string{
		filepath.Join(run.workdir, "bin"),
		filepath.Join(run.workdir, "node_modules", ".bin"),
		filepath.Join(run.workdir, "venv", "bin"),
	}
	for _, dir := range planted {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		for _, name := range []string{"cat", "go"} {
			if err := os.WriteFile(filepath.Join(dir, name), []byte("#!/bin/sh\necho FORGED\n"), 0o755); err != nil { //nolint:gosec // an executable test script
				t.Fatal(err)
			}
		}
	}
	// The planted directories come first on both the server's PATH and,
	// here, the test's own, so only the harness's trusted PATH avoids them.
	t.Setenv("PATH", strings.Join(append(planted, os.Getenv("PATH")), string(os.PathListSeparator)))
	lock := filepath.Join(run.workdir, "package-lock.json")
	if err := os.WriteFile(lock, []byte("the real lockfile\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := readAsAccount(t.Context(), sb, lock)
	if err != nil || string(got) != "the real lockfile\n" {
		t.Errorf("readAsAccount = %q, %v; want the real file, not a planted cat's", got, err)
	}
	var out bytes.Buffer
	if err := sb.Run(t.Context(), []string{"go", "version"}, &out); err != nil || strings.Contains(out.String(), "FORGED") {
		t.Errorf("go version = %q, %v; want the toolchain's, not a planted go", out.String(), err)
	}
}

func TestTheVenvIsListedByTheHarnesssPythonNotOnePlantedInIt(t *testing.T) {
	run := newTestRun(t, &fakeInstaller{})
	sb := run.h.sandbox()
	venv := filepath.Join(run.workdir, "venv")
	if err := os.MkdirAll(run.workdir, 0o700); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := sb.Run(t.Context(), []string{"python3", "-m", "venv", "--without-pip", venv}, &out); err != nil {
		t.Skipf("no python3 venv here: %v %s", err, out.String())
	}
	out.Reset()
	if err := sb.Run(t.Context(), []string{"python3", "-I", "-c", "import sysconfig, sys; print(sysconfig.get_path('purelib', vars={'base': sys.argv[1], 'platbase': sys.argv[1]}))", venv}, &out); err != nil {
		t.Fatal(err)
	}
	site := strings.TrimSpace(out.String())
	// What a wheel installs: its metadata, and console scripts named pip
	// and python3 that replace the venv's own.
	for name, body := range map[string]string{
		"evilpy-1.0.0.dist-info/METADATA": "Metadata-Version: 2.1\nName: evilpy\nVersion: 1.0.0\n",
		"httpx-0.27.0.dist-info/METADATA": "Metadata-Version: 2.1\nName: httpx\nVersion: 0.27.0\n",
		"../../../bin/pip":                "#!/bin/sh\necho FORGED==9.9.9\n",
		"../../../bin/python3":            "#!/bin/sh\necho FORGED==9.9.9\n",
	} {
		file := filepath.Join(site, name)
		if err := os.MkdirAll(filepath.Dir(file), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(file); err != nil && !os.IsNotExist(err) {
			t.Fatal(err)
		}
		if err := os.WriteFile(file, []byte(body), 0o755); err != nil { //nolint:gosec // the console scripts must be executable
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", filepath.Join(venv, "bin")+string(os.PathListSeparator)+os.Getenv("PATH"))
	got, err := listVenv(t.Context(), sb, venv)
	if err != nil || string(got) != "evilpy==1.0.0\nhttpx==0.27.0\n" {
		t.Errorf("listVenv = %q, %v; want the venv's real distributions, not a planted pip's", got, err)
	}
}
