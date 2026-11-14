package harness

import (
	"os"
	"strings"
	"testing"
)

// TestTheRunsEndKillsEveryProcessOfTheAccount needs root, to switch users.
// A process the server left in a session of its own, outside the process
// group Close stops, ends with the run too. It sleeps a minute, so a
// failing test ends, saying it exited rather than was killed.
func TestTheRunsEndKillsEveryProcessOfTheAccount(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("switching to the account needs root")
	}
	if _, err := os.Stat(setpriv); err != nil {
		t.Skipf("no %s here", setpriv)
	}
	// A uid no one else on this machine uses.
	a := Account{Name: "dev", UID: 61235, GID: 61235, Switch: true}
	run := newIdleRunWith(t, &fakeInstaller{}, func(c *Config) {
		a.Home = c.Account.Home
		c.Account = a
	})
	lingering := a.command(t.Context(), "/", a.env("/usr/bin:/bin"), []string{"/usr/bin/setsid", "/bin/sleep", "60"})
	lingering.SysProcAttr.Setpgid = false
	if err := lingering.Start(); err != nil {
		t.Fatal(err)
	}
	run.h.Close()
	if err := lingering.Wait(); err == nil || !strings.Contains(err.Error(), "killed") {
		t.Errorf("the process the server left ended with %v, want killed", err)
	}
}
