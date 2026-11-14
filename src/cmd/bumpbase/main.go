// Command bumpbase moves sandbox/Dockerfile to another tag of Lambda's
// MicroVM base image in the public ECR gallery. It rewrites the tag, the
// tag's manifest list digest, the Amazon Linux 2023 release the tag's arm64
// image was built from (the ADD line of its history), and every package dnf
// installs to the newest version that release's repository holds. Wiring
// only; the work is in internal/basebump.
//
//	go run ./cmd/bumpbase -dockerfile ../sandbox/Dockerfile al2023-minimal.2026.11.12.03
//
// The gallery lists the tags at gallery.ecr.aws/lambda/microvms.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/JairJosafath/mcp-customs/src/internal/basebump"
)

func main() {
	dockerfile := flag.String("dockerfile", "../sandbox/Dockerfile", "the Dockerfile to rewrite")
	flag.Usage = func() {
		fmt.Fprintln(flag.CommandLine.Output(), "usage: bumpbase [-dockerfile path] al2023-minimal.YYYY.MM.DD.HH")
		flag.PrintDefaults()
	}
	flag.Parse()
	if err := bump(context.Background(), basebump.Public(), *dockerfile, flag.Args(), os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "bumpbase:", err)
		os.Exit(1)
	}
}

// bump rewrites the Dockerfile at path to the one tag args names, from src,
// and says what changed on out. The file is left as it was on any error.
func bump(ctx context.Context, src basebump.Source, path string, args []string, out io.Writer) error {
	if len(args) != 1 {
		return errors.New("name one tag, such as al2023-minimal.2026.11.12.03")
	}
	tag := args[0]
	// The file is read and written through its directory, as one name in it.
	dir, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		return fmt.Errorf("read the Dockerfile: %w", err)
	}
	defer func() { _ = dir.Close() }()
	name := filepath.Base(path)
	info, err := dir.Stat(name)
	if err != nil {
		return fmt.Errorf("read the Dockerfile: %w", err)
	}
	text, err := dir.ReadFile(name)
	if err != nil {
		return fmt.Errorf("read the Dockerfile: %w", err)
	}
	from, err := basebump.Parse(string(text))
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	to := basebump.Base{Tag: tag}
	if to.Digest, to.Release, err = src.Image(ctx, tag); err != nil {
		return err
	}
	if to.Packages, err = src.Packages(ctx, to.Release, from.Names()); err != nil {
		return err
	}
	rewritten, err := basebump.Rewrite(string(text), to)
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	if err := dir.WriteFile(name, []byte(rewritten), info.Mode().Perm()); err != nil {
		return fmt.Errorf("write the Dockerfile: %w", err)
	}
	fmt.Fprintf(out, "%s -> %s\n%s -> %s\n%s -> %s\n", from.Tag, to.Tag, from.Digest, to.Digest, from.Release, to.Release)
	for _, name := range from.Names() {
		if from.Packages[name] != to.Packages[name] {
			fmt.Fprintf(out, "%s: %s -> %s\n", name, from.Packages[name], to.Packages[name])
		}
	}
	return nil
}
