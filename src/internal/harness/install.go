package harness

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// Ecosystem is where a server under test comes from.
type Ecosystem string

// The ecosystems of the Harness API's install call.
const (
	EcosystemGo     Ecosystem = "go"
	EcosystemNPM    Ecosystem = "npm"
	EcosystemPyPI   Ecosystem = "pypi"
	EcosystemRemote Ecosystem = "remote"
)

// A Package is a server to install, pinned to one version.
type Package struct {
	Ecosystem Ecosystem
	Name      string
	Version   string
}

// The shapes of a pinned name and version in each ecosystem. A name never
// starts with "-", so it can't be read as a flag.
var (
	goName      = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._~-]*(/[A-Za-z0-9._~-]+)+$`)
	goVersion   = regexp.MustCompile(`^v\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$`)
	npmName     = regexp.MustCompile(`^(@[a-z0-9][a-z0-9._~-]*/)?[a-z0-9][a-z0-9._~-]*$`)
	npmVersion  = regexp.MustCompile(`^\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$`)
	pypiName    = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?$`)
	pypiVersion = regexp.MustCompile(`^\d+(\.\d+)*((a|b|rc|\.post|\.dev)\d+)*$`)
	goMajor     = regexp.MustCompile(`^v\d+$`)
)

// ParsePackage reads the install call's kind and "name@version" ref into a
// pinned package. A range, a tag such as "latest" or a remote URL is refused.
func ParsePackage(kind, ref string) (Package, error) {
	at := strings.LastIndex(ref, "@")
	if at <= 0 || at == len(ref)-1 {
		return Package{}, fmt.Errorf("the ref %q is not name@version", ref)
	}
	p := Package{Ecosystem: Ecosystem(kind), Name: ref[:at], Version: ref[at+1:]}
	var name, version *regexp.Regexp
	switch p.Ecosystem {
	case EcosystemGo:
		name, version = goName, goVersion
	case EcosystemNPM:
		name, version = npmName, npmVersion
	case EcosystemPyPI:
		name, version = pypiName, pypiVersion
	case EcosystemRemote:
		return Package{}, errors.New("remote servers are not supported by this harness yet")
	default:
		return Package{}, fmt.Errorf("unknown kind %q: want go, npm or pypi", kind)
	}
	if !name.MatchString(p.Name) {
		return Package{}, fmt.Errorf("%q is not a %s package name", p.Name, kind)
	}
	if !version.MatchString(p.Version) {
		return Package{}, fmt.Errorf("%q is not one pinned %s version", p.Version, kind)
	}
	return p, nil
}

// Installed is what an install produced.
type Installed struct {
	// Log is the install's output.
	Log string
	// Resolved is the resolved dependency set: go.sum's equivalent, the npm
	// lockfile, or pip's pinned requirements with their hashes. It is what
	// the resolver chose before any code of the package ran, never what the
	// installed files say of themselves. Its SHA-256 identifies the install.
	Resolved []byte
	// Command starts the installed server, the start call's default.
	Command []string
}

// A Sandbox is where an Installer works: the server's working directory,
// the environment its commands get, and a way to run them as the
// unprivileged account.
type Sandbox struct {
	Workdir string
	Env     []string
	// Run runs args as the account in Workdir with Env, writing the output
	// to out.
	Run func(ctx context.Context, args []string, out io.Writer) error
	// KillAll kills every process of the account, so nothing an install
	// step started outlives it. Nil kills nothing.
	KillAll func(ctx context.Context) error
}

// An Installer installs a package into a sandbox.
type Installer interface {
	Install(ctx context.Context, p Package, sb Sandbox) (Installed, error)
}

// Toolchain installs with the ecosystems' own tools: go, npm, and pip in a
// virtual environment. Everything it runs, and every file of the install it
// reads, goes through the sandbox as the unprivileged account, so a
// package can't make the harness read its own files.
type Toolchain struct{}

// Install installs p into sb.Workdir.
func (Toolchain) Install(ctx context.Context, p Package, sb Sandbox) (Installed, error) {
	var log bytes.Buffer
	var out Installed
	var err error
	switch p.Ecosystem {
	case EcosystemGo:
		out, err = installGo(ctx, p, sb, &log)
	case EcosystemNPM:
		out, err = installNPM(ctx, p, sb, &log)
	case EcosystemPyPI:
		out, err = installPyPI(ctx, p, sb, &log)
	case EcosystemRemote:
		err = errors.New("remote servers are not installed")
	default:
		err = fmt.Errorf("unknown ecosystem %q", p.Ecosystem)
	}
	out.Log = log.String()
	return out, err
}

func installGo(ctx context.Context, p Package, sb Sandbox, log io.Writer) (Installed, error) {
	if err := step(ctx, sb, log, "go", "install", p.Name+"@"+p.Version); err != nil {
		return Installed{}, err
	}
	bin := filepath.Join(sb.Workdir, "bin", goBinary(p.Name))
	var info bytes.Buffer
	if err := sb.Run(ctx, []string{"go", "version", "-m", bin}, &info); err != nil {
		return Installed{}, fmt.Errorf("read the modules of %s: %w", bin, err)
	}
	return Installed{Resolved: goModules(info.String()), Command: []string{bin}}, nil
}

// goBinary is the name go install gives a package's binary: its last path
// element, or the one before a major version suffix such as /v2.
func goBinary(pkg string) string {
	parts := strings.Split(pkg, "/")
	last := parts[len(parts)-1]
	if len(parts) > 1 && goMajor.MatchString(last) {
		return parts[len(parts)-2]
	}
	return last
}

// goModules keeps the module lines of `go version -m`: the main module,
// each dependency and each replacement, with their go.sum hashes.
func goModules(info string) []byte {
	var out strings.Builder
	for line := range strings.SplitSeq(info, "\n") {
		fields := strings.Fields(line)
		if len(fields) > 0 && (fields[0] == "mod" || fields[0] == "dep" || fields[0] == "=>") {
			out.WriteString(strings.Join(fields, " ") + "\n")
		}
	}
	return []byte(out.String())
}

// installNPM resolves the lockfile first, with no script run, and reads it
// before anything of the package runs; npm ci then installs exactly that
// lockfile, scripts and all. Nothing an install script does to
// package-lock.json afterwards can change the reported set.
func installNPM(ctx context.Context, p Package, sb Sandbox, log io.Writer) (Installed, error) {
	if err := step(ctx, sb, log, "npm", "install", "--prefix", sb.Workdir, "--no-audit", "--no-fund",
		"--save-exact", "--package-lock-only", "--ignore-scripts", p.Name+"@"+p.Version); err != nil {
		return Installed{}, err
	}
	lock, err := readAsAccount(ctx, sb, filepath.Join(sb.Workdir, "package-lock.json"))
	if err != nil {
		return Installed{}, err
	}
	if err := step(ctx, sb, log, "npm", "ci", "--prefix", sb.Workdir, "--no-audit", "--no-fund"); err != nil {
		return Installed{}, err
	}
	manifest, err := readAsAccount(ctx, sb, filepath.Join(sb.Workdir, "node_modules", p.Name, "package.json"))
	if err != nil {
		return Installed{}, err
	}
	bin, err := npmBinary(p.Name, manifest)
	if err != nil {
		return Installed{}, err
	}
	return Installed{Resolved: lock, Command: []string{filepath.Join(sb.Workdir, "node_modules", ".bin", bin)}}, nil
}

// npmBinary is the command a package's package.json names: its only bin,
// or the one named like the package.
func npmBinary(name string, manifest []byte) (string, error) {
	var pkg struct {
		Bin json.RawMessage `json:"bin"`
	}
	if err := json.Unmarshal(manifest, &pkg); err != nil {
		return "", fmt.Errorf("read the package.json of %s: %w", name, err)
	}
	unscoped := path.Base(name)
	var one string
	if err := json.Unmarshal(pkg.Bin, &one); err == nil && one != "" {
		return unscoped, nil
	}
	var many map[string]string
	if err := json.Unmarshal(pkg.Bin, &many); err != nil || len(many) == 0 {
		return "", fmt.Errorf("%s names no command in its package.json; give the start call one", name)
	}
	if _, ok := many[unscoped]; ok {
		return unscoped, nil
	}
	if len(many) == 1 {
		for bin := range many {
			return path.Base(bin), nil
		}
	}
	names := make([]string, 0, len(many))
	for bin := range many {
		names = append(names, bin)
	}
	sort.Strings(names)
	return "", fmt.Errorf("%s names several commands (%s); give the start call one", name, strings.Join(names, ", "))
}

// step runs one install command, logging it and its output, then kills
// whatever the command left running as the account, so no process of the
// package can change the install's files after the step returns.
func step(ctx context.Context, sb Sandbox, log io.Writer, args ...string) error {
	fmt.Fprintf(log, "$ %s\n", strings.Join(args, " "))
	err := sb.Run(ctx, args, log)
	if sb.KillAll != nil {
		if killErr := sb.KillAll(ctx); killErr != nil {
			return fmt.Errorf("end what %s left running: %w", strings.Join(args[:2], " "), killErr)
		}
	}
	if err != nil {
		return fmt.Errorf("%s: %w", strings.Join(args[:2], " "), err)
	}
	return nil
}

func readAsAccount(ctx context.Context, sb Sandbox, file string) ([]byte, error) {
	var out bytes.Buffer
	if err := sb.Run(ctx, []string{"cat", "--", file}, &out); err != nil {
		return nil, fmt.Errorf("read %s: %w", file, err)
	}
	return out.Bytes(), nil
}
