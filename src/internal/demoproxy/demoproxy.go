// Package demoproxy makes the files of a Go module proxy that serves the
// demo MCP servers' versions (docs/contracts.md, "The demo proxy"). The
// stack serves them from its bucket, so the live rug pull needs no account
// on a public registry: publishing the mail demo's v1.0.1 is writing these
// files there.
//
// A demo lives in this repository as a package of the src module, its
// versions as build tags; a published version is a module of its own whose
// default build is that version, because `go install module@version` can't
// pass tags.
package demoproxy

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"strings"
	"time"

	"golang.org/x/mod/module"
	"golang.org/x/mod/semver"
)

// ModulePrefix is the path every demo module starts with. The sandbox skips
// the checksum database for it, and for nothing else.
const ModulePrefix = "github.com/JairJosafath/mcp-customs/demo"

// A Release is a version of a demo and the time it says it was published.
type Release struct {
	Version string
	Time    time.Time
}

// A Module is a demo server as the proxy serves it: its module path, its
// package's directory in the src module, and its releases, oldest first.
type Module struct {
	Path     string
	Dir      string
	Releases []Release
}

// Modules are the demo servers the proxy serves.
var Modules = []Module{
	{
		Path: ModulePrefix + "/mail",
		Dir:  "demo/mail",
		Releases: []Release{
			{"v1.0.0", time.Date(2026, 11, 1, 9, 0, 0, 0, time.UTC)},
			{"v1.0.1", time.Date(2026, 11, 14, 9, 0, 0, 0, time.UTC)},
		},
	},
	{
		Path:     ModulePrefix + "/weather",
		Dir:      "demo/weather",
		Releases: []Release{{"v1.0.0", time.Date(2026, 11, 1, 9, 0, 0, 0, time.UTC)}},
	},
}

// ErrUnknownVersion says no demo has a release of that version.
var ErrUnknownVersion = errors.New("no demo has a release of that version")

// Files are the proxy's files when version is published: for each demo,
// every release up to and including version, as paths relative to the
// proxy's root (`<module>/@v/list`, `.info`, `.mod`, `.zip` and
// `<module>/@latest`). src is the src module's directory. Publishing an
// earlier version again takes the later ones back off the list.
func Files(src fs.FS, version string) (map[string][]byte, error) {
	if !semver.IsValid(version) {
		return nil, fmt.Errorf("%q: %w", version, ErrUnknownVersion)
	}
	files := map[string][]byte{}
	known := false
	for _, m := range Modules {
		var published []Release
		for _, r := range m.Releases {
			if semver.Compare(r.Version, version) <= 0 {
				published = append(published, r)
			}
			known = known || r.Version == version
		}
		if err := addModule(files, src, m, published); err != nil {
			return nil, err
		}
	}
	if !known {
		return nil, fmt.Errorf("%q: %w", version, ErrUnknownVersion)
	}
	return files, nil
}

// addModule adds the proxy files of m's releases to files.
func addModule(files map[string][]byte, src fs.FS, m Module, releases []Release) error {
	if len(releases) == 0 {
		return nil
	}
	root, err := module.EscapePath(m.Path)
	if err != nil {
		return fmt.Errorf("escape %s: %w", m.Path, err)
	}
	var list strings.Builder
	for _, r := range releases {
		v, err := module.EscapeVersion(r.Version)
		if err != nil {
			return fmt.Errorf("escape %s: %w", r.Version, err)
		}
		at := root + "/@v/" + v
		zip, err := moduleZip(src, m, r.Version)
		if err != nil {
			return err
		}
		info, err := infoOf(r)
		if err != nil {
			return err
		}
		files[at+".info"] = info
		files[at+".mod"] = goMod(m.Path)
		files[at+".zip"] = zip
		files[root+"/@latest"] = info
		list.WriteString(r.Version + "\n")
	}
	files[root+"/@v/list"] = []byte(list.String())
	return nil
}

// infoOf is a release's .info: its version and time, as JSON.
func infoOf(r Release) ([]byte, error) {
	info, err := json.Marshal(struct {
		Version string
		Time    time.Time
	}{r.Version, r.Time})
	if err != nil {
		return nil, fmt.Errorf("encode the info of %s: %w", r.Version, err)
	}
	return info, nil
}

// goMod is a demo module's go.mod: the standard library is all it needs.
func goMod(path string) []byte {
	return []byte("module " + path + "\n\ngo 1.26\n")
}

// ErrBadProxy says a GOPROXY list holds something other than https URLs.
var ErrBadProxy = errors.New("a Go module proxy list must be https:// URLs with a host, separated by commas")

// SplitProxyList is a GOPROXY-style list, the proxies asked in turn, each
// after the one before answered 404 or 410: each an https URL with a host
// and no query, fragment or user. "direct" and "off" are refused.
func SplitProxyList(list string) ([]string, error) {
	var out []string
	for item := range strings.SplitSeq(list, ",") {
		u, err := url.Parse(item)
		if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
			return nil, ErrBadProxy
		}
		out = append(out, item)
	}
	return out, nil
}
