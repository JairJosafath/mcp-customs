package harness

import (
	"context"
	"errors"
	"io"
	"slices"
	"strings"
	"testing"
)

func TestParsePackageAcceptsOnlyPinnedVersions(t *testing.T) {
	for _, tc := range []struct {
		kind, ref string
		want      Package
		ok        bool
	}{
		{"go", "github.com/acme/weather@v1.2.3", Package{EcosystemGo, "github.com/acme/weather", "v1.2.3"}, true},
		{"go", "github.com/acme/weather/cmd/server/v2@v2.0.0-rc.1", Package{EcosystemGo, "github.com/acme/weather/cmd/server/v2", "v2.0.0-rc.1"}, true},
		{"npm", "@acme/weather@1.0.1", Package{EcosystemNPM, "@acme/weather", "1.0.1"}, true},
		{"npm", "weather-mcp@0.3.0-beta.2", Package{EcosystemNPM, "weather-mcp", "0.3.0-beta.2"}, true},
		{"pypi", "mcp-server-fetch@2025.4.7", Package{EcosystemPyPI, "mcp-server-fetch", "2025.4.7"}, true},
		{"pypi", "weather@1.0rc1", Package{EcosystemPyPI, "weather", "1.0rc1"}, true},
		{"go", "github.com/acme/weather@latest", Package{}, false},
		{"go", "github.com/acme/weather@master", Package{}, false},
		{"go", "weather@v1.0.0", Package{}, false},
		{"go", "-modfile=x/y@v1.0.0", Package{}, false},
		{"npm", "weather@~1.0.0", Package{}, false},
		{"npm", "weather@1.x", Package{}, false},
		{"npm", "@acme/weather", Package{}, false},
		{"npm", "weather@", Package{}, false},
		{"pypi", "weather@>=1.0", Package{}, false},
		{"pypi", "weather@1.0.*", Package{}, false},
		{"pypi", "weather @ git+https://x@1.0", Package{}, false},
		{"remote", "https://mcp.example.com@1", Package{}, false},
		{"", "weather@1.0.0", Package{}, false},
	} {
		got, err := ParsePackage(tc.kind, tc.ref)
		if (err == nil) != tc.ok || got != tc.want {
			t.Errorf("ParsePackage(%q, %q) = %+v, %v", tc.kind, tc.ref, got, err)
		}
	}
}

// fakeRun is a sandbox's runner that records each command and answers
// with the output given for the whole command or, failing that, for its
// first two words, or fails.
type fakeRun struct {
	ran     [][]string
	outputs map[string]string
	fail    string
}

func (f *fakeRun) run(_ context.Context, args []string, out io.Writer) error {
	f.ran = append(f.ran, args)
	key := strings.Join(args[:min(2, len(args))], " ")
	if key == f.fail {
		_, _ = io.WriteString(out, "it broke\n")
		return errors.New("exit status 1")
	}
	answer, ok := f.outputs[strings.Join(args, " ")]
	if !ok {
		answer = f.outputs[key]
	}
	_, err := io.WriteString(out, answer)
	return err
}

// pipReportJSON is pip's report for weather-mcp 1.0.0 and httpx.
const pipReportJSON = `{"version":"1","install":[
{"download_info":{"archive_info":{"hashes":{"sha256":"` + hashA + `"}}},"requested":true,"metadata":{"name":"weather-mcp","version":"1.0.0"}},
{"download_info":{"archive_info":{"hashes":{"sha256":"` + hashB + `"}}},"requested":false,"metadata":{"name":"httpx","version":"0.27.0"}}]}`

const (
	hashA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	hashB = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	// pipSetAB is the set pipReportJSON gives.
	pipSetAB = "httpx==0.27.0 --hash=sha256:" + hashB + "\nweather-mcp==1.0.0 --hash=sha256:" + hashA + "\n"
)

const goVersionM = `/w/bin/weather: go1.26.0
	path	github.com/acme/weather
	mod	github.com/acme/weather	v1.2.3	h1:aaa=
	dep	golang.org/x/net	v0.30.0	h1:bbb=
	=>	golang.org/x/net	v0.31.0	h1:ccc=
	build	-buildmode=exe
	build	GOOS=linux
`

func TestToolchainInstallsEachEcosystemAsTheAccount(t *testing.T) {
	for name, tc := range map[string]struct {
		pkg      Package
		outputs  map[string]string
		wantRan  [][]string
		resolved string
		command  []string
	}{
		"a Go module": {
			pkg:     Package{EcosystemGo, "github.com/acme/weather", "v1.2.3"},
			outputs: map[string]string{"go install": "go: downloading github.com/acme/weather v1.2.3\n", "go version": goVersionM},
			wantRan: [][]string{
				{"go", "install", "github.com/acme/weather@v1.2.3"},
				{"go", "version", "-m", "/w/bin/weather"},
			},
			resolved: "mod github.com/acme/weather v1.2.3 h1:aaa=\ndep golang.org/x/net v0.30.0 h1:bbb=\n=> golang.org/x/net v0.31.0 h1:ccc=\n",
			command:  []string{"/w/bin/weather"},
		},
		"an npm package, its lockfile read before any of its scripts run": {
			pkg: Package{EcosystemNPM, "@acme/weather", "1.0.1"},
			outputs: map[string]string{
				"npm install":                 "added 12 packages\n",
				"cat -- /w/package-lock.json": `{"lockfileVersion":3}`,
				"cat -- /w/node_modules/@acme/weather/package.json": `{"name":"@acme/weather","bin":{"weather":"dist/index.js"}}`,
			},
			wantRan: [][]string{
				{"npm", "install", "--prefix", "/w", "--no-audit", "--no-fund", "--save-exact", "--package-lock-only", "--ignore-scripts", "@acme/weather@1.0.1"},
				{"cat", "--", "/w/package-lock.json"},
				{"npm", "ci", "--prefix", "/w", "--no-audit", "--no-fund"},
				{"cat", "--", "/w/node_modules/@acme/weather/package.json"},
			},
			resolved: `{"lockfileVersion":3}`,
			command:  []string{"/w/node_modules/.bin/weather"},
		},
		"a PyPI package, its set the resolver's before anything is installed": {
			pkg: Package{EcosystemPyPI, "weather-mcp", "1.0.0"},
			outputs: map[string]string{
				"python3 -I": "httpx==0.27.0\nweather-mcp==1.0.0\n",
				"cat --":     pipReportJSON,
			},
			wantRan: [][]string{
				{"python3", "-m", "venv", "/w/venv"},
				{"python3", "-I", "-c", venvDistributions, "/w/venv"},
				{"/w/venv/bin/pip", "install", "--disable-pip-version-check", "--dry-run", "--ignore-installed", "--report", "/w/pip-report.json", "weather-mcp==1.0.0"},
				{"cat", "--", "/w/pip-report.json"},
				{"python3", "-I", "-c", writeFile, "/w/pip-requirements.txt", pipSetAB},
				{"/w/venv/bin/pip", "install", "--disable-pip-version-check", "--no-deps", "--require-hashes", "-r", "/w/pip-requirements.txt"},
				{"python3", "-I", "-c", venvDistributions, "/w/venv"},
			},
			resolved: pipSetAB,
			command:  []string{"/w/venv/bin/weather-mcp"},
		},
	} {
		f := &fakeRun{outputs: tc.outputs}
		got, err := Toolchain{}.Install(t.Context(), tc.pkg, Sandbox{Workdir: "/w", Run: f.run})
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if !slices.EqualFunc(f.ran, tc.wantRan, slices.Equal) {
			t.Errorf("%s: ran %q, want %q", name, f.ran, tc.wantRan)
		}
		if string(got.Resolved) != tc.resolved {
			t.Errorf("%s: resolved %q, want %q", name, got.Resolved, tc.resolved)
		}
		if !slices.Equal(got.Command, tc.command) {
			t.Errorf("%s: command %q, want %q", name, got.Command, tc.command)
		}
		if !strings.HasPrefix(got.Log, "$ ") {
			t.Errorf("%s: the log %q does not show the commands", name, got.Log)
		}
	}
}

func TestToolchainAnswersTheLogOfAFailedInstall(t *testing.T) {
	f := &fakeRun{fail: "npm install"}
	got, err := Toolchain{}.Install(t.Context(), Package{EcosystemNPM, "weather", "1.0.0"}, Sandbox{Workdir: "/w", Run: f.run})
	if err == nil || !strings.Contains(got.Log, "it broke") {
		t.Errorf("a failed install = %q, %v; want the error and its log", got.Log, err)
	}
}

func TestGoBinaryIsNamedAsGoInstallNamesIt(t *testing.T) {
	for pkg, want := range map[string]string{
		"github.com/acme/weather":            "weather",
		"github.com/acme/weather/v2":         "weather",
		"github.com/acme/tools/cmd/forecast": "forecast",
	} {
		if got := goBinary(pkg); got != want {
			t.Errorf("goBinary(%q) = %q, want %q", pkg, got, want)
		}
	}
}

func TestNPMBinaryIsTheCommandThePackageNames(t *testing.T) {
	for _, tc := range []struct {
		name, manifest, want string
		ok                   bool
	}{
		{"@acme/weather", `{"bin":"dist/cli.js"}`, "weather", true},
		{"weather", `{"bin":{"weather":"a.js","weather-admin":"b.js"}}`, "weather", true},
		{"weather", `{"bin":{"wx":"a.js"}}`, "wx", true},
		{"weather", `{"bin":{"a":"a.js","b":"b.js"}}`, "", false},
		{"weather", `{"main":"index.js"}`, "", false},
		{"weather", `not json`, "", false},
	} {
		got, err := npmBinary(tc.name, []byte(tc.manifest))
		if got != tc.want || (err == nil) != tc.ok {
			t.Errorf("npmBinary(%q, %s) = %q, %v", tc.name, tc.manifest, got, err)
		}
	}
}
