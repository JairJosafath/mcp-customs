// Command demopublish writes the demo Go module proxy's files for a version
// of the demos into a new or empty directory: the stack's deploy copies
// them to its bucket (infra/demo_proxy.ts), and `make demo-build` writes
// them to look at. Wiring only; the work is in internal/demoproxy.
//
//	go run ./cmd/demopublish -version v1.0.1 -out ../cdk.out/demo-proxy
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/JairJosafath/mcp-customs/src/internal/demoproxy"
)

func main() {
	version := flag.String("version", "", "the demos' version to publish, such as v1.0.1")
	out := flag.String("out", "", "a new or empty directory to write the proxy's files into")
	src := flag.String("src", ".", "the src module's directory")
	flag.Parse()
	if err := publish(*src, *version, *out); err != nil {
		fmt.Fprintln(os.Stderr, "demopublish:", err)
		os.Exit(1)
	}
}

// errNotEmpty says the directory to write into already holds files.
var errNotEmpty = errors.New("it holds files already")

func publish(src, version, out string) error {
	if out == "" {
		return errors.New("name the directory to write into with -out")
	}
	files, err := demoproxy.Files(os.DirFS(src), version)
	if err != nil {
		return err
	}
	// A new or empty directory, so it holds this version's files and
	// nothing left from another.
	if err := os.MkdirAll(out, 0o750); err != nil {
		return fmt.Errorf("make %s: %w", out, err)
	}
	if left, err := os.ReadDir(out); err != nil || len(left) > 0 {
		return fmt.Errorf("%s must be empty: %w", out, errors.Join(err, errNotEmpty))
	}
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		p := filepath.Join(out, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
			return fmt.Errorf("make the directory of %s: %w", name, err)
		}
		if err := os.WriteFile(p, files[name], 0o600); err != nil {
			return fmt.Errorf("write %s: %w", name, err)
		}
	}
	return nil
}
