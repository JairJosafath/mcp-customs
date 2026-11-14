package harness

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// installPyPI asks pip's resolver for the dependency set before anything is
// installed, in a clean venv, and reads its report itself; pip then installs
// exactly that set, each file checked against the hash the resolver saw.
// The reported set is the report's, never a listing of the venv afterwards:
// a wheel can ship .dist-info files under its .data directory and make the
// installed venv say anything of itself. The listing is only compared with
// the set, and what differs is written to the log.
func installPyPI(ctx context.Context, p Package, sb Sandbox, log io.Writer) (Installed, error) {
	venv := filepath.Join(sb.Workdir, "venv")
	if err := step(ctx, sb, log, "python3", "-m", "venv", venv); err != nil {
		return Installed{}, err
	}
	before, err := listVenv(ctx, sb, venv)
	if err != nil {
		return Installed{}, err
	}
	pip := filepath.Join(venv, "bin", "pip")
	report := filepath.Join(sb.Workdir, "pip-report.json")
	if err := step(ctx, sb, log, pip, "install", "--disable-pip-version-check", "--dry-run", "--ignore-installed",
		"--report", report, p.Name+"=="+p.Version); err != nil {
		return Installed{}, err
	}
	raw, err := readAsAccount(ctx, sb, report)
	if err != nil {
		return Installed{}, err
	}
	set, err := pipSet(raw, p.Name)
	if err != nil {
		return Installed{}, err
	}
	requirements := filepath.Join(sb.Workdir, "pip-requirements.txt")
	if err := writeAsAccount(ctx, sb, requirements, set); err != nil {
		return Installed{}, err
	}
	if err := step(ctx, sb, log, pip, "install", "--disable-pip-version-check", "--no-deps", "--require-hashes",
		"-r", requirements); err != nil {
		return Installed{}, err
	}
	after, err := listVenv(ctx, sb, venv)
	if err != nil {
		return Installed{}, err
	}
	noteClaims(log, before, after, set)
	return Installed{Resolved: set, Command: []string{filepath.Join(venv, "bin", p.Name)}, Source: sitePackages(venv)}, nil
}

// pipReport is the part of pip's installation report (format version 1)
// the set is made from.
type pipReport struct {
	Version string `json:"version"`
	Install []struct {
		DownloadInfo struct {
			URL         string `json:"url"`
			ArchiveInfo *struct {
				Hashes map[string]string `json:"hashes"`
			} `json:"archive_info"`
		} `json:"download_info"`
		Requested bool `json:"requested"`
		Metadata  struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"metadata"`
	} `json:"install"`
}

var (
	pipReportedVersion = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.+!_-]*$`)
	sha256Hex          = regexp.MustCompile(`^[0-9a-f]{64}$`)
	pypiSeparators     = regexp.MustCompile(`[-_.]+`)
)

// pipSet is the dependency set of pip's report as a requirements file: one
// "name==version --hash=sha256:..." a line, sorted by normalized name. It
// pins every file, so `pip install --no-deps --require-hashes -r` installs
// exactly what the resolver chose, and nothing that only shares a name.
// The report must name the requested package, and every entry must be a
// wheel with its SHA-256: a VCS or local directory can't be pinned, and an
// sdist is built with build dependencies no hash pins.
func pipSet(raw []byte, requested string) ([]byte, error) {
	var report pipReport
	if err := json.Unmarshal(raw, &report); err != nil {
		return nil, fmt.Errorf("read pip's report: %w", err)
	}
	if report.Version != "1" {
		return nil, fmt.Errorf("pip's report is version %q; the harness reads version 1", report.Version)
	}
	lines := map[string]string{}
	found := false
	for _, d := range report.Install {
		name, version := d.Metadata.Name, d.Metadata.Version
		if !pypiName.MatchString(name) || !pipReportedVersion.MatchString(version) {
			return nil, fmt.Errorf("pip's report names %q %q, not a package and version", name, version)
		}
		var sum string
		if d.DownloadInfo.ArchiveInfo != nil {
			sum = d.DownloadInfo.ArchiveInfo.Hashes["sha256"]
		}
		if !sha256Hex.MatchString(sum) {
			return nil, fmt.Errorf("pip resolved %s %s from no archive with a SHA-256, so it can't be pinned", name, version)
		}
		if !isWheel(d.DownloadInfo.URL) {
			return nil, fmt.Errorf("pip resolved %s %s to an sdist, not a wheel: building it needs build dependencies --require-hashes can't pin", name, version)
		}
		key := normalizePyPI(name)
		if _, dup := lines[key]; dup {
			return nil, fmt.Errorf("pip's report names %s twice", name)
		}
		lines[key] = name + "==" + version + " --hash=sha256:" + sum + "\n"
		found = found || (d.Requested && key == normalizePyPI(requested))
	}
	if !found {
		return nil, fmt.Errorf("pip's report does not install %s", requested)
	}
	keys := make([]string, 0, len(lines))
	for k := range lines {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var out strings.Builder
	for _, k := range keys {
		out.WriteString(lines[k])
	}
	return []byte(out.String()), nil
}

// isWheel says whether the file pip downloads from rawURL is a wheel.
func isWheel(rawURL string) bool {
	u, err := url.Parse(rawURL)
	return err == nil && strings.HasSuffix(path.Base(u.Path), ".whl")
}

// normalizePyPI is a distribution name as PEP 503 compares them.
func normalizePyPI(name string) string {
	return pypiSeparators.ReplaceAllString(strings.ToLower(name), "-")
}

// noteClaims writes to log what the venv's metadata says that the set does
// not: distributions the install's files claim, and ones of the set that
// don't show. The set stays the resolver's; this is evidence for the log.
func noteClaims(log io.Writer, before, after, set []byte) {
	want := map[string]bool{}
	for line := range strings.Lines(string(set)) {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		name, version, _ := strings.Cut(fields[0], "==")
		want[normalizePyPI(name)+"=="+version] = true
	}
	had := map[string]bool{}
	for line := range strings.Lines(string(before)) {
		had[pinOf(line)] = true
	}
	got := map[string]bool{}
	for line := range strings.Lines(string(after)) {
		pin := pinOf(line)
		got[pin] = true
		if !want[pin] && !had[pin] {
			fmt.Fprintf(log, "note: the venv's metadata claims %s, which the resolver did not install\n", strings.TrimSpace(line))
		}
	}
	for pin := range want {
		if !got[pin] {
			fmt.Fprintf(log, "note: the venv's metadata does not show %s, which the resolver installed\n", pin)
		}
	}
}

// pinOf is a listing's "name==version" line with its name normalized.
func pinOf(line string) string {
	name, version, _ := strings.Cut(strings.TrimSpace(line), "==")
	return normalizePyPI(name) + "==" + version
}

// venvDistributions prints the distributions in the site-packages of the
// venv named by its argument, one "name==version" a line, sorted. It reads
// their metadata only, with the standard library: no code of the venv runs.
// It asks sysconfig for the venv scheme by name: a Debian-patched Python's
// default scheme points elsewhere and would list nothing.
const venvDistributions = `import importlib.metadata as m, sys, sysconfig
site = sysconfig.get_path("purelib", "venv", vars={"base": sys.argv[1], "platbase": sys.argv[1]})
names = {d.metadata["Name"] + "==" + d.version for d in m.distributions(path=[site]) if d.metadata["Name"]}
print("".join(n + "\n" for n in sorted(names, key=str.lower)), end="")
`

// listVenv is what the venv's metadata says is installed, read by the
// harness's own python3 (isolated, found on the trusted PATH), never by a
// file in the venv: the package can replace venv/bin/pip and
// venv/bin/python3 with console scripts of its own. A venv always holds
// pip, so an empty listing means the wrong directory was read: an error.
func listVenv(ctx context.Context, sb Sandbox, venv string) ([]byte, error) {
	var out bytes.Buffer
	if err := sb.Run(ctx, []string{"python3", "-I", "-c", venvDistributions, venv}, &out); err != nil {
		return nil, fmt.Errorf("list the venv: %w", err)
	}
	if out.Len() == 0 {
		return nil, fmt.Errorf("the venv %s lists no distribution, not even pip: its site-packages was not found", venv)
	}
	return out.Bytes(), nil
}

// writeFile writes the file named by its first argument, which must not
// exist (a link planted there is refused), with its second argument.
const writeFile = `import sys
with open(sys.argv[1], "x", encoding="utf-8") as f:
    f.write(sys.argv[2])
`

// writeAsAccount writes data to file as the account, with the harness's own
// python3, so the harness never writes into a directory the package owns.
func writeAsAccount(ctx context.Context, sb Sandbox, file string, data []byte) error {
	if err := sb.Run(ctx, []string{"python3", "-I", "-c", writeFile, file, string(data)}, io.Discard); err != nil {
		return fmt.Errorf("write %s: %w", file, err)
	}
	return nil
}
