package harness

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

// Nothing under /proc is read, the harness's own files included, which
// the account's thread opens because it shares the harness's thread
// group, nor any file reached through a link to one.
func TestFakeTimeAppliesReadsNothingUnderProc(t *testing.T) {
	open, _ := reachTree(t)
	self := "/proc/" + strconv.Itoa(os.Getpid())
	for _, command := range []string{
		"/proc/self/maps",
		"/proc/self/status",
		self + "/maps",
		"/proc/thread-self/maps",
		"/proc/version",
		link(t, open, "maps-link", "/proc/self/maps"),
		link(t, open, "version-link", "/proc/version"),
	} {
		wantUnreadable(t, open, command)
	}
}

// A file of the account's own group, readable by the group alone, is read,
// as the kernel would let the account; one whose group bits refuse it is
// not, whatever the bits for others say.
func TestFakeTimeAppliesHonoursTheAccountsGroup(t *testing.T) {
	open, _ := reachTree(t)
	for _, tc := range []struct {
		mode os.FileMode
		gid  int
		want string
	}{
		{0o640, int(stranger.GID), appliesNo},
		{0o604, int(stranger.GID), appliesUnknown},
		{0o640, 0, appliesUnknown},
	} {
		file := filepath.Join(open, "sh-"+strconv.FormatUint(uint64(tc.mode), 8)+"-"+strconv.Itoa(tc.gid))
		must(t, os.WriteFile(file, staticELF(), 0o600))
		must(t, os.Chown(file, 0, tc.gid))
		must(t, os.Chmod(file, tc.mode))
		if applies, why := stranger.fakeTimeApplies([]string{file}, ""); applies != tc.want {
			t.Errorf("a %#o file of group %d: %s (%s), want %s", tc.mode, tc.gid, applies, why, tc.want)
		}
	}
}
