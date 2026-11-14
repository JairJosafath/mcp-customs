package main

import (
	"os/user"
	"slices"
	"strings"
	"testing"

	"github.com/JairJosafath/mcp-customs/src/internal/harness"
)

var dev = &user.User{Username: "dev", Uid: "1000", Gid: "1000", HomeDir: "/home/dev"}

func TestAccountForRefusesToRunTheServerAsTheHarnessOrRoot(t *testing.T) {
	for name, tc := range map[string]struct {
		u    *user.User
		euid int
		want string
	}{
		"the harness is not root":        {dev, 1000, "must run as root"},
		"the harness is another user":    {dev, 1001, "must run as root"},
		"the account is root":            {&user.User{Username: "root", Uid: "0", Gid: "0", HomeDir: "/root"}, 0, "is root"},
		"the account is in group root":   {&user.User{Username: "dev", Uid: "1000", Gid: "0", HomeDir: "/home/dev"}, 0, "is root"},
		"the account has no numeric uid": {&user.User{Username: "dev", Uid: "S-1-5-21", Gid: "1000"}, 0, "uid of dev"},
	} {
		_, err := accountFor(tc.u, tc.euid)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v, want one saying %q", name, err, tc.want)
		}
	}
}

func TestAccountForSwitchesToTheUnprivilegedUserAsRoot(t *testing.T) {
	got, err := accountFor(dev, 0)
	want := harness.Account{Name: "dev", Home: "/home/dev", UID: 1000, GID: 1000, Switch: true}
	if err != nil || got != want {
		t.Errorf("accountFor(dev, 0) = %+v, %v; want %+v", got, err, want)
	}
}

func TestTheServerGetsAPathOfItsOwnNotTheHarnesss(t *testing.T) {
	t.Setenv("PATH", "/root/.local/bin:/root/go/bin:/usr/bin")
	got := configFor(harness.Account{Name: "dev", Home: "/home/dev"}).Path
	if got != serverPath {
		t.Errorf("the server's PATH = %q, want %q, not the harness's", got, serverPath)
	}
	for _, dir := range strings.Split(got, ":") {
		if !strings.HasPrefix(dir, "/usr/") && dir != "/bin" {
			t.Errorf("the server's PATH holds %s, outside the system's directories", dir)
		}
	}
	for _, want := range []string{"/usr/local/go/bin", "/usr/local/node/bin", "/usr/bin"} {
		if !slices.Contains(strings.Split(got, ":"), want) {
			t.Errorf("the server's PATH lacks %s, where the image's toolchains are", want)
		}
	}
}

func TestTheProxysTrustDirectoryIsOutsideTheServersHome(t *testing.T) {
	if err := trustOutside(trustDir, "/home/dev"); err != nil {
		t.Errorf("trustDir %s: %v", trustDir, err)
	}
	for _, tc := range []struct{ dir, home string }{
		{"/home/dev/.config/mcp-customs", "/home/dev"},
		{"/home/dev", "/home/dev"},
		{"/home/dev/../dev/trust", "/home/dev"},
	} {
		if err := trustOutside(tc.dir, tc.home); err == nil {
			t.Errorf("trustOutside(%s, %s) = nil, want it refused", tc.dir, tc.home)
		}
	}
	if err := trustOutside("/home/developer/trust", "/home/dev"); err != nil {
		t.Errorf("a sibling of the home was refused: %v", err)
	}
}
