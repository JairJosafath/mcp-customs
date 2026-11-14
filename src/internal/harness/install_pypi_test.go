package harness

import (
	"bytes"
	"context"
	"errors"
	"io"
	"slices"
	"strings"
	"testing"
)

func TestPipSetPinsEveryFileTheResolverChose(t *testing.T) {
	got, err := pipSet([]byte(pipReportJSON), "Weather_MCP")
	if err != nil || string(got) != pipSetAB {
		t.Errorf("pipSet = %q, %v; want %q", got, err, pipSetAB)
	}
}

func TestPipSetRefusesAReportItCantPin(t *testing.T) {
	file := func(url, name, version, sum string, requested bool) string {
		r := "false"
		if requested {
			r = "true"
		}
		return `{"download_info":{"url":"` + url + `","archive_info":{"hashes":{"sha256":"` + sum + `"}}},"requested":` + r +
			`,"metadata":{"name":"` + name + `","version":"` + version + `"}}`
	}
	entry := func(name, version, sum string, requested bool) string {
		return file("https://files.example/"+name+"-"+version+"-py3-none-any.whl", name, version, sum, requested)
	}
	report := func(entries ...string) string {
		return `{"version":"1","install":[` + strings.Join(entries, ",") + `]}`
	}
	for name, raw := range map[string]string{
		"not JSON":                     "WARNING: pip says something",
		"another report version":       `{"version":"2","install":[]}`,
		"no requested package":         report(entry("httpx", "0.27.0", hashB, false)),
		"another package requested":    report(entry("goodpkg", "3.1.4", hashA, true)),
		"a file with no hash":          report(entry("weather-mcp", "1.0.0", "", true)),
		"a hash that is not a SHA-256": report(entry("weather-mcp", "1.0.0", "md5", true)),
		"a directory, not an archive":  `{"version":"1","install":[{"download_info":{"dir_info":{}},"requested":true,"metadata":{"name":"weather-mcp","version":"1.0.0"}}]}`,
		"a name that is a flag":        report(entry("weather-mcp", "1.0.0", hashA, true), entry("-e", "1", hashB, false)),
		"a version with a space":       report(entry("weather-mcp", "1.0.0 --index-url=x", hashA, true)),
		"one package twice":            report(entry("weather-mcp", "1.0.0", hashA, true), entry("Weather.MCP", "1.0.1", hashB, false)),
		"an sdist":                     report(entry("weather-mcp", "1.0.0", hashA, true), file("https://files.example/oldlib-0.1.tar.gz", "oldlib", "0.1", hashB, false)),
		"no file at all":               report(file("", "weather-mcp", "1.0.0", hashA, true)),
		"a wheel only in its fragment": report(file("https://files.example/w-1.0.0.tar.gz#.whl", "weather-mcp", "1.0.0", hashA, true)),
	} {
		if got, err := pipSet([]byte(raw), "weather-mcp"); err == nil {
			t.Errorf("%s: pipSet = %q, want an error", name, got)
		}
	}
}

func TestAnSdistOnlyDependencyFailsTheInstallWithALogLineNamingIt(t *testing.T) {
	report := strings.Replace(pipReportJSON, "httpx-0.27.0-py3-none-any.whl", "httpx-0.27.0.tar.gz", 1)
	f := &fakeRun{outputs: map[string]string{"python3 -I": "pip==26.0\n", "cat --": report}}
	got, err := Toolchain{}.Install(t.Context(), Package{EcosystemPyPI, "weather-mcp", "1.0.0"}, Sandbox{Workdir: "/w", Run: f.run})
	if err == nil {
		t.Fatalf("install = %+v, want it to fail", got)
	}
	if want := "the install failed: pip resolved httpx 0.27.0 to an sdist"; !strings.Contains(got.Log, want) {
		t.Errorf("log %q does not say %q", got.Log, want)
	}
	for _, args := range f.ran {
		if slices.Contains(args, "--require-hashes") {
			t.Errorf("ran %q after the report named an sdist", args)
		}
	}
}

func TestEachInstallStepKillsWhatItLeftRunning(t *testing.T) {
	for _, fail := range []string{"", "npm ci"} {
		f := &fakeRun{fail: fail, outputs: map[string]string{
			"cat -- /w/node_modules/weather/package.json": `{"bin":"index.js"}`,
		}}
		var kills []int
		sb := Sandbox{Workdir: "/w", Run: f.run, KillAll: func(context.Context) error {
			kills = append(kills, len(f.ran))
			return nil
		}}
		_, err := Toolchain{}.Install(t.Context(), Package{EcosystemNPM, "weather", "1.0.0"}, sb)
		if (err != nil) != (fail != "") {
			t.Errorf("failing %q: %v", fail, err)
		}
		// After the lockfile step (1 command run) and after npm ci (3).
		if want := []int{1, 3}; len(kills) != len(want) || kills[0] != want[0] || kills[1] != want[1] {
			t.Errorf("failing %q: killed after commands %v, want %v", fail, kills, want)
		}
	}
	sb := Sandbox{Workdir: "/w", Run: (&fakeRun{}).run, KillAll: func(context.Context) error { return errors.New("no") }}
	if err := step(t.Context(), sb, io.Discard, "npm", "ci"); err == nil || !strings.Contains(err.Error(), "left running") {
		t.Errorf("a failed kill = %v, want the step to fail", err)
	}
}

func TestAnEmptyVenvListingIsAnErrorNotAnEmptySet(t *testing.T) {
	f := &fakeRun{outputs: map[string]string{"python3 -I": ""}}
	if got, err := listVenv(t.Context(), Sandbox{Workdir: "/w", Run: f.run}, "/w/venv"); err == nil {
		t.Errorf("listVenv = %q, want an error", got)
	}
	if !strings.Contains(venvDistributions, `get_path("purelib", "venv",`) {
		t.Error("the listing does not name sysconfig's venv scheme")
	}
}

func TestNoteClaimsSkipsBlankLinesOfTheSet(t *testing.T) {
	var log bytes.Buffer
	noteClaims(&log, nil, []byte("weather-mcp==1.0.0\n"), []byte("\n   \nweather-mcp==1.0.0 --hash=sha256:"+hashA+"\n\t\n"))
	if log.Len() != 0 {
		t.Errorf("log %q, want nothing to note", log.String())
	}
}

func TestTheLogNotesWhatTheVenvClaimsBeyondTheSet(t *testing.T) {
	var log bytes.Buffer
	before := []byte("pip==26.0\n")
	after := []byte("FORGED==9.9.9\ngoodpkg==3.1.4\nhttpx==0.27.0\npip==26.0\n")
	noteClaims(&log, before, after, []byte(pipSetAB))
	for _, want := range []string{"claims FORGED==9.9.9", "claims goodpkg==3.1.4", "does not show weather-mcp==1.0.0"} {
		if !strings.Contains(log.String(), want) {
			t.Errorf("log %q does not say %q", log.String(), want)
		}
	}
	if strings.Contains(log.String(), "httpx") || strings.Contains(log.String(), "pip==") {
		t.Errorf("log %q notes what agrees", log.String())
	}
}

// pipNoWheel is what pip writes when --only-binary leaves a dependency
// with nothing to install.
const pipNoWheel = "ERROR: Could not find a version that satisfies the requirement httpx==0.27.0 (from weather-mcp) (from versions: none)\n" +
	"ERROR: No matching distribution found for httpx==0.27.0\n"

func TestTheDryRunResolvesWheelsOnlySoNoSdistsBuildBackendRuns(t *testing.T) {
	f := &fakeRun{outputs: map[string]string{"python3 -I": "pip==26.0\n", "cat --": pipReportJSON}}
	var dryRun []string
	run := func(ctx context.Context, args []string, out io.Writer) error {
		if slices.Contains(args, "--dry-run") {
			dryRun = args
			_, _ = io.WriteString(out, pipNoWheel)
			return errors.New("exit status 1")
		}
		return f.run(ctx, args, out)
	}
	got, err := Toolchain{}.Install(t.Context(), Package{EcosystemPyPI, "weather-mcp", "1.0.0"}, Sandbox{Workdir: "/w", Run: run})
	if !slices.Contains(dryRun, "--only-binary=:all:") {
		t.Errorf("dry run %q, want --only-binary=:all:", dryRun)
	}
	if err == nil {
		t.Fatalf("install = %+v, want it to fail", got)
	}
	for _, want := range []string{"No matching distribution found for httpx==0.27.0", "the install failed:"} {
		if !strings.Contains(got.Log, want) {
			t.Errorf("log %q does not say %q", got.Log, want)
		}
	}
	for _, args := range f.ran {
		if slices.Contains(args, "--require-hashes") {
			t.Errorf("ran %q after the dry run failed", args)
		}
	}
}
