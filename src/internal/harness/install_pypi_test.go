package harness

import (
	"bytes"
	"context"
	"errors"
	"io"
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
	entry := func(name, version, sum string, requested bool) string {
		r := "false"
		if requested {
			r = "true"
		}
		return `{"download_info":{"archive_info":{"hashes":{"sha256":"` + sum + `"}}},"requested":` + r +
			`,"metadata":{"name":"` + name + `","version":"` + version + `"}}`
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
	} {
		if got, err := pipSet([]byte(raw), "weather-mcp"); err == nil {
			t.Errorf("%s: pipSet = %q, want an error", name, got)
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
