package harness

import (
	"path/filepath"
	"strings"

	"golang.org/x/mod/module"
)

// goModuleDir is the module cache's directory of the main module named in
// resolved, `go version -m`'s module lines: where /source reads a Go
// server's code. Empty when resolved names no main module.
func goModuleDir(workdir string, resolved []byte) string {
	for line := range strings.SplitSeq(string(resolved), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 || fields[0] != "mod" {
			continue
		}
		dir, err := module.EscapePath(fields[1])
		if err != nil {
			return ""
		}
		version, err := module.EscapeVersion(fields[2])
		if err != nil {
			return ""
		}
		return filepath.Join(workdir, ".go", "pkg", "mod", filepath.FromSlash(dir+"@"+version))
	}
	return ""
}

// sitePackages is the venv's site-packages, where /source reads a Python
// server's code and its dependencies'. Empty unless there is exactly one.
func sitePackages(venv string) string {
	dirs, err := filepath.Glob(filepath.Join(venv, "lib", "python3*", "site-packages"))
	if err != nil || len(dirs) != 1 {
		return ""
	}
	return dirs[0]
}
