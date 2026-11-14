// Command demopublish writes the demo Go module proxy's files for a version
// of the demos into a new directory, for `make demo-publish` to copy to the
// stack's bucket. Wiring only; the work is in internal/demoproxy.
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
	out := flag.String("out", "", "a directory that does not exist yet, to write the proxy's files into")
	src := flag.String("src", ".", "the src module's directory")
	flag.Parse()
	if err := publish(*src, *version, *out); err != nil {
		fmt.Fprintln(os.Stderr, "demopublish:", err)
		os.Exit(1)
	}
}

func publish(src, version, out string) error {
	if out == "" {
		return errors.New("name the directory to write into with -out")
	}
	files, err := demoproxy.Files(os.DirFS(src), version)
	if err != nil {
		return err
	}
	// A new directory, so a copy of it to the bucket holds this version's
	// files and nothing left from another.
	if err := os.Mkdir(out, 0o750); err != nil {
		return fmt.Errorf("make %s: %w", out, err)
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
		fmt.Println(name)
	}
	return nil
}
