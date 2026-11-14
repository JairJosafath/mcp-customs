package harness

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
)

// stranger is an account that is neither root nor the test's user.
var stranger = Account{UID: 4242, GID: 4242}

// reachTree is a directory the stranger can search, holding open, which
// it can search too, and hidden, which it can't: root's, 0700. hidden
// holds sub, 0755, and each of open and sub hold sh, a 0644 static ELF.
func reachTree(t *testing.T) (open, hidden string) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("needs root, to own a directory the account can't search")
	}
	root := t.TempDir()
	// t.TempDir's own parent is 0700: open it, so only hidden is closed.
	for _, dir := range []string{filepath.Dir(root), root} {
		must(t, os.Chmod(dir, 0o755)) //nolint:gosec // a directory anyone may search, as an install's is
	}
	open, hidden = filepath.Join(root, "open"), filepath.Join(root, "hidden")
	must(t, os.Mkdir(open, 0o755))                         //nolint:gosec // as above
	must(t, os.Mkdir(hidden, 0o700))                       // root's alone
	must(t, os.Mkdir(filepath.Join(hidden, "sub"), 0o755)) //nolint:gosec // searchable, but only through hidden
	for _, dir := range []string{open, filepath.Join(hidden, "sub")} {
		must(t, os.WriteFile(filepath.Join(dir, "sh"), staticELF(), 0o644)) //nolint:gosec // readable by anyone who can reach it
	}
	return open, hidden
}

// wantUnreadable fails unless command answers unknown, with the why a
// missing file of the same name gets.
func wantUnreadable(t *testing.T, open, command string) {
	t.Helper()
	_, missing := stranger.fakeTimeApplies([]string{filepath.Join(open, "missing", filepath.Base(command))}, "")
	if applies, why := stranger.fakeTimeApplies([]string{command}, ""); applies != appliesUnknown || why != missing {
		t.Errorf("%s: %s (%s), want unknown (%s)", command, applies, why, missing)
	}
}

// link is a symlink in open, named name, to target.
func link(t *testing.T, open, name, target string) string {
	t.Helper()
	l := filepath.Join(open, name)
	must(t, os.Symlink(target, l))
	return l
}

func TestFakeTimeAppliesOnlyToFilesTheAccountCanReach(t *testing.T) {
	open, hidden := reachTree(t)
	if applies, why := stranger.fakeTimeApplies([]string{link(t, open, "reachable", filepath.Join(open, "sh"))}, ""); applies != appliesNo {
		t.Errorf("a link to a file the account can reach: %s (%s), want no", applies, why)
	}
	wantUnreadable(t, open, link(t, open, "weather", filepath.Join(hidden, "sub", "sh")))
	// The sandbox's interpreters, and this machine's, all root's and 0755.
	for _, real := range []string{"/usr/local/node/bin/node", "/usr/local/bin/python3", "/opt/node22/bin/node", "/bin/sh"} {
		if _, err := os.Stat(real); err != nil {
			continue
		}
		if applies, got := stranger.fakeTimeApplies([]string{real}, ""); applies != appliesYes {
			t.Errorf("%s: %s (%s), want yes", real, applies, got)
		}
	}
}

func TestFakeTimeAppliesToNothingReachedThroughProcMagicLinks(t *testing.T) {
	open, hidden := reachTree(t)
	sub := filepath.Join(hidden, "sub")
	dir, err := os.Open(sub)
	must(t, err)
	t.Cleanup(func() { _ = dir.Close() })
	file, err := os.Open(filepath.Join(sub, "sh"))
	must(t, err)
	t.Cleanup(func() { _ = file.Close() })
	child := exec.Command("sleep", "60")
	child.Dir = sub
	must(t, child.Start())
	t.Cleanup(func() { _ = child.Process.Kill(); _ = child.Wait() })
	t.Chdir(sub)
	self := "/proc/" + strconv.Itoa(os.Getpid())
	viaFD := "/proc/self/fd/" + strconv.Itoa(int(dir.Fd())) + "/sh"
	for _, command := range []string{
		viaFD,
		self + "/fd/" + strconv.Itoa(int(dir.Fd())) + "/sh",
		"/proc/self/fd/" + strconv.Itoa(int(file.Fd())),
		"/proc/self/cwd/sh",
		"/proc/" + strconv.Itoa(child.Process.Pid) + "/cwd/sh",
		// 0444, but only a process that may ptrace root's child opens it.
		"/proc/" + strconv.Itoa(child.Process.Pid) + "/maps",
		link(t, open, "sh-link", viaFD),
	} {
		wantUnreadable(t, open, command)
	}
	// The test binary sits in go test's 0700 build directory.
	exe, err := os.Executable()
	must(t, err)
	if applies, _ := stranger.fakeTimeApplies([]string{exe}, ""); applies == appliesUnknown {
		wantUnreadable(t, open, "/proc/self/exe")
	}
}
