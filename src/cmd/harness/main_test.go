package main

import (
	"os/user"
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
