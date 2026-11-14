package demoproxy

import (
	"bytes"
	"errors"
	"fmt"
	"go/build/constraint"
	"go/parser"
	"go/token"
	"io"
	"io/fs"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/mod/module"
	modzip "golang.org/x/mod/zip"
)

// sharedDir is the package every demo imports, copied into each module as
// internal/mcp.
const sharedDir = "demo/mcp"

// srcImport is how a demo imports sharedDir in the src module.
const srcImport = "github.com/JairJosafath/mcp-customs/src/" + sharedDir

// versionTag is a build tag that names a demo version: v1_0_1 for v1.0.1.
var versionTag = regexp.MustCompile(`^v\d+_\d+_\d+$`)

// ErrSource says a demo's source can't be made into a module.
var ErrSource = errors.New("the demo's source can't be made into a module")

// moduleZip is the module zip of m at version: m's package and the shared
// one, each file built for version and its build line taken off, so the
// module's default build is that version.
func moduleZip(src fs.FS, m Module, version string) ([]byte, error) {
	tag := strings.ReplaceAll(version, ".", "_")
	files := map[string][]byte{"go.mod": goMod(m.Path)}
	for _, pkg := range []struct{ from, to string }{{m.Dir, ""}, {sharedDir, "internal/mcp/"}} {
		if err := addSources(files, src, pkg.from, pkg.to, tag, m.Path); err != nil {
			return nil, err
		}
	}
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	zipFiles := make([]modzip.File, 0, len(names))
	for _, name := range names {
		zipFiles = append(zipFiles, memFile{name, files[name]})
	}
	var buf bytes.Buffer
	if err := modzip.Create(&buf, module.Version{Path: m.Path, Version: version}, zipFiles); err != nil {
		return nil, fmt.Errorf("zip %s@%s: %w", m.Path, version, err)
	}
	return buf.Bytes(), nil
}

// addSources adds the Go files of dir that build with tag, but not its
// tests, to files under prefix, their build lines taken off and the shared
// package's import made the module's own.
func addSources(files map[string][]byte, src fs.FS, dir, prefix, tag, modPath string) error {
	entries, err := fs.ReadDir(src, dir)
	if err != nil {
		return fmt.Errorf("read %s: %w", dir, err)
	}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		body, err := fs.ReadFile(src, path.Join(dir, name))
		if err != nil {
			return fmt.Errorf("read %s: %w", name, err)
		}
		body, keep, err := forVersion(body, tag)
		if err != nil {
			return fmt.Errorf("%s/%s: %w", dir, name, err)
		}
		if !keep {
			continue
		}
		body = bytes.ReplaceAll(body, []byte(strconv.Quote(srcImport)), []byte(strconv.Quote(modPath+"/internal/mcp")))
		if err := standardOrOwn(body, modPath); err != nil {
			return fmt.Errorf("%s/%s: %w", dir, name, err)
		}
		files[prefix+name] = body
	}
	return nil
}

// forVersion is body built for the version named by tag: false when its
// build line leaves it out, and with the line taken off when it keeps it.
// A build line may name version tags only.
func forVersion(body []byte, tag string) ([]byte, bool, error) {
	lines := bytes.SplitAfter(body, []byte("\n"))
	for i, line := range lines {
		text := strings.TrimSpace(string(line))
		if strings.HasPrefix(text, "package ") {
			break
		}
		if !constraint.IsGoBuild(text) {
			continue
		}
		expr, err := constraint.Parse(text)
		if err != nil {
			return nil, false, fmt.Errorf("%w: %w", ErrSource, err)
		}
		onlyVersions := true
		keep := expr.Eval(func(t string) bool {
			onlyVersions = onlyVersions && versionTag.MatchString(t)
			return t == tag
		})
		if !onlyVersions {
			return nil, false, fmt.Errorf("%w: its build line names a tag that is not a version", ErrSource)
		}
		return bytes.Join(append(lines[:i:i], lines[i+1:]...), nil), keep, nil
	}
	return body, true, nil
}

// standardOrOwn checks that body imports only the standard library and
// the module's own packages, so the module's go.mod needs nothing else.
func standardOrOwn(body []byte, modPath string) error {
	f, err := parser.ParseFile(token.NewFileSet(), "", body, parser.ImportsOnly)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrSource, err)
	}
	for _, imp := range f.Imports {
		p, err := strconv.Unquote(imp.Path.Value)
		if err != nil {
			return fmt.Errorf("%w: %w", ErrSource, err)
		}
		first, _, _ := strings.Cut(p, "/")
		if strings.Contains(first, ".") && p != modPath && !strings.HasPrefix(p, modPath+"/") {
			return fmt.Errorf("%w: it imports %s", ErrSource, p)
		}
	}
	return nil
}

// memFile is a file of a module zip, held in memory.
type memFile struct {
	name string
	body []byte
}

func (f memFile) Path() string                 { return f.name }
func (f memFile) Lstat() (fs.FileInfo, error)  { return memInfo(f), nil }
func (f memFile) Open() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(f.body)), nil }

// memInfo is a memFile's fs.FileInfo: a regular file.
type memInfo memFile

func (i memInfo) Name() string       { return path.Base(i.name) }
func (i memInfo) Size() int64        { return int64(len(i.body)) }
func (i memInfo) Mode() fs.FileMode  { return 0o644 }
func (i memInfo) ModTime() time.Time { return time.Time{} }
func (i memInfo) IsDir() bool        { return false }
func (i memInfo) Sys() any           { return nil }
