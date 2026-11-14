package main

import (
	"log/slog"
	"net/netip"
	"os/user"
	"slices"
	"strings"
	"testing"

	"github.com/JairJosafath/mcp-customs/src/internal/egress"
	"github.com/JairJosafath/mcp-customs/src/internal/harness"
	"github.com/JairJosafath/mcp-customs/src/internal/ownapi"
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

func TestAnInstallMayGetOnlyTheDemoProxyOfTheStacksAPI(t *testing.T) {
	cases := []struct {
		list string
		gets []string
		err  bool
	}{
		{"", nil, false},
		{
			"https://abc.execute-api.us-east-1.amazonaws.com/goproxy,https://proxy.golang.org",
			[]string{"https://abc.execute-api.us-east-1.amazonaws.com/goproxy/"},
			false,
		},
		{"https://demo.example:8443/goproxy/", []string{"https://demo.example:8443/goproxy/"}, false},
		{"https://demo.example,direct", nil, true},
		{"http://demo.example", nil, true},
	}
	for _, c := range cases {
		allow, err := installAllowFor(c.list)
		if (err != nil) != c.err || !slices.Equal(allow.gets, c.gets) {
			t.Errorf("%q: gets %v, %v; want %v, error %v", c.list, allow.gets, err, c.gets, c.err)
		}
		// The registries stay allowed whole; the stack's API host never is.
		if err == nil && (!slices.Equal(allow.hosts, egress.RegistryHosts) || slices.Contains(allow.hosts, "abc.execute-api.us-east-1.amazonaws.com")) {
			t.Errorf("%q: hosts %v, want the registries alone", c.list, allow.hosts)
		}
	}
}

func TestServeRefusesToStartWithoutTheStacksOwnAPIHost(t *testing.T) {
	for _, host := range []string{"", "api.example.com"} {
		t.Setenv("API_HOST", host)
		// An unknown user would fail too; the API host must fail first.
		t.Setenv("HARNESS_USER", "no-such-user-mcp-customs")
		err := serve(slog.New(slog.DiscardHandler))
		if err == nil || !strings.HasPrefix(err.Error(), "API_HOST: ") {
			t.Errorf("API_HOST %q: serve = %v, want it refused for the API host", host, err)
		}
	}
}

func TestTheProxysGuardRefusesTheAPIsAddressesButForTheDemoProxy(t *testing.T) {
	const apiHost = "abc.execute-api.eu-west-1.amazonaws.com"
	api, err := ownapi.Parse(apiHost)
	if err != nil {
		t.Fatal(err)
	}
	allow, err := installAllowFor("https://" + apiHost + "/goproxy,https://proxy.golang.org")
	if err != nil {
		t.Fatal(err)
	}
	g := guardFor(api, apiHost, allow)
	if !slices.Equal(g.Exempt, []string{apiHost}) || !slices.Equal(g.RefusedNames, []string{apiHost}) {
		t.Errorf("exempt %v, refused names %v; want the demo proxy's host, and the API host", g.Exempt, g.RefusedNames)
	}
	if g.Refused == nil || !g.Refused(netip.MustParseAddr("3.248.245.10")) || g.Refused(netip.MustParseAddr("198.51.100.7")) {
		t.Error("the guard must refuse API Gateway's ranges for the API's region, and nothing else")
	}
}
