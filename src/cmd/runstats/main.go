// Command runstats prints the numbers docs/results.md quotes, counted from
// docs/runs.md and git log; hack/runs-stats runs it from the repository's
// root. It reads the repository and never writes.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"

	"github.com/JairJosafath/mcp-customs/src/internal/runstats"
)

func main() {
	repo := flag.String("repo", ".", "the repository's root")
	runs := flag.String("runs", "docs/runs.md", "the runs table, relative to -repo")
	rev := flag.String("rev", "HEAD", "the commit to count at")
	flag.Parse()
	if err := run(os.Stdout, *repo, *runs, *rev, gitIn(*repo)); err != nil {
		fmt.Fprintln(os.Stderr, "runs-stats:", err)
		os.Exit(1)
	}
}

// git runs a git command and answers its output.
type git func(args ...string) (string, error)

func gitIn(repo string) git {
	return func(args ...string) (string, error) {
		out, err := exec.Command("git", append([]string{"-C", repo}, args...)...).Output() //nolint:gosec // G204: fixed git subcommands; the arguments are this command's own flags
		if err != nil {
			return "", fmt.Errorf("git %s: %w", strings.Join(args, " "), err)
		}
		return string(out), nil
	}
}

// errShallow refuses a shallow clone, whose log is missing the oldest
// merges: counting there undercounts without a sign.
var errShallow = errors.New("the clone is shallow, so git log misses the oldest merges; run git fetch --unshallow first")

// run counts runs.md as committed at rev, and the pull requests merged on
// rev's first-parent history.
func run(w io.Writer, repo, runs, rev string, g git) error {
	shallow, err := g("rev-parse", "--is-shallow-repository")
	if err != nil {
		return err
	}
	if strings.TrimSpace(shallow) == "true" {
		return errShallow
	}
	head, err := g("rev-parse", "--short", rev)
	if err != nil {
		return err
	}
	runsCommit, err := g("log", "-1", "--format=%h", rev, "--", runs)
	if err != nil {
		return err
	}
	table, err := g("show", rev+":"+runs)
	if err != nil {
		return err
	}
	rows, err := runstats.ParseRuns(strings.NewReader(table))
	if err != nil {
		return fmt.Errorf("%s/%s: %w", repo, runs, err)
	}
	log, err := g("log", "--first-parent", "--format=%s", rev)
	if err != nil {
		return err
	}
	st, err := runstats.Compute(rows, runstats.ParseMerges(log))
	if err != nil {
		return err
	}
	st.Write(w, runstats.Source{RunsPath: runs, RunsCommit: strings.TrimSpace(runsCommit), Head: strings.TrimSpace(head)})
	return nil
}
