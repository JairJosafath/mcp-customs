package harness

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFakeTimeAppliesOnlyToFilesTheAccountCanReach(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root, to own a directory the account can't search")
	}
	hidden := t.TempDir() // 0700, root's
	file := filepath.Join(hidden, "sh")
	must(t, os.WriteFile(file, staticELF(), 0o644)) //nolint:gosec // readable by anyone, but in a directory only root can search
	open := t.TempDir()
	must(t, os.Chmod(open, 0o755)) //nolint:gosec // a directory anyone may search, as an install's is
	stranger := Account{UID: 4242, GID: 4242}
	why := func(target string) (string, string) {
		link := filepath.Join(open, "weather")
		_ = os.Remove(link)
		must(t, os.Symlink(target, link))
		return stranger.fakeTimeApplies([]string{link}, "")
	}
	_, missing := why(filepath.Join(open, "missing"))
	if applies, got := why(file); applies != appliesUnknown || got != missing {
		t.Errorf("a link into a directory the account can't search: %s (%s), want unknown (%s)", applies, got, missing)
	}
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
