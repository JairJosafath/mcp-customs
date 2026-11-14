// Command demopublish writes the demo Go module proxy's files for the demo
// versions a JSON file names (infra/demo-versions.json) into a new or empty
// directory: the stack's deploy copies them to its bucket
// (infra/demo_proxy.ts), and `make demo-build` writes them to look at.
// Wiring only; the work is in internal/demoproxy.
//
//	go run ./cmd/demopublish -versions-file ../infra/demo-versions.json -out ../cdk.out/demo-proxy
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path"
	"sort"

	"github.com/JairJosafath/mcp-customs/src/internal/demoproxy"
)

func main() {
	versionsFile := flag.String("versions-file", "", `a JSON file of the versions to publish, by demo: {"mail": "v1.0.1", "weather": "v1.0.0"}`)
	out := flag.String("out", "", "a new or empty directory to write the proxy's files into")
	src := flag.String("src", ".", "the src module's directory")
	flag.Parse()
	if err := publish(*src, *versionsFile, *out); err != nil {
		fmt.Fprintln(os.Stderr, "demopublish:", err)
		os.Exit(1)
	}
}

// errNotEmpty says the directory to write into already holds files.
var errNotEmpty = errors.New("it holds files already")

func publish(src, versionsFile, out string) error {
	if out == "" || versionsFile == "" {
		return errors.New("name the versions file with -versions-file and the directory to write into with -out")
	}
	data, err := os.ReadFile(versionsFile)
	if err != nil {
		return fmt.Errorf("read the versions: %w", err)
	}
	versions, err := demoproxy.ParseVersions(data)
	if err != nil {
		return fmt.Errorf("%s: %w", versionsFile, err)
	}
	files, err := demoproxy.Files(os.DirFS(src), versions)
	if err != nil {
		return fmt.Errorf("%s: %w", versionsFile, err)
	}
	// A new or empty directory, so it holds this version's files and
	// nothing left from another.
	if err := os.MkdirAll(out, 0o750); err != nil {
		return fmt.Errorf("make %s: %w", out, err)
	}
	if left, err := os.ReadDir(out); err != nil || len(left) > 0 {
		return fmt.Errorf("%s must be empty: %w", out, errors.Join(err, errNotEmpty))
	}
	// Every file goes under out, through a root that refuses a path out of it.
	root, err := os.OpenRoot(out)
	if err != nil {
		return fmt.Errorf("open %s: %w", out, err)
	}
	defer func() { _ = root.Close() }()
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if err := root.MkdirAll(path.Dir(name), 0o750); err != nil {
			return fmt.Errorf("make the directory of %s: %w", name, err)
		}
		if err := root.WriteFile(name, files[name], 0o600); err != nil {
			return fmt.Errorf("write %s: %w", name, err)
		}
	}
	return nil
}
