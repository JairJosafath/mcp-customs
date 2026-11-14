package main

import (
	"bytes"
	"errors"
	"os"
	"strings"
	"testing"
)

// fakeGit answers the git commands run asks, from the runstats fixtures.
func fakeGit(t *testing.T, shallow string) git {
	t.Helper()
	read := func(name string) string {
		b, err := os.ReadFile("../../internal/runstats/testdata/" + name)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		return string(b)
	}
	return func(args ...string) (string, error) {
		switch strings.Join(args, " ") {
		case "rev-parse --is-shallow-repository":
			return shallow + "\n", nil
		case "rev-parse --short HEAD":
			return "bbbbbbb\n", nil
		case "log -1 --format=%h HEAD -- docs/runs.md":
			return "aaaaaaa\n", nil
		case "show HEAD:docs/runs.md":
			return read("runs.md"), nil
		case "log --first-parent --format=%s HEAD":
			return read("gitlog.txt"), nil
		}
		return "", errors.New("unexpected git " + strings.Join(args, " "))
	}
}

func TestRunPrintsTheFixturesNumbers(t *testing.T) {
	var out bytes.Buffer
	if err := run(&out, ".", "docs/runs.md", "HEAD", fakeGit(t, "false")); err != nil {
		t.Fatalf("run: %v", err)
	}
	want, err := os.ReadFile("../../internal/runstats/testdata/stats.txt")
	if err != nil {
		t.Fatal(err)
	}
	if out.String() != string(want) {
		t.Errorf("printed\n%s\nwant\n%s", out.String(), want)
	}
}

func TestRunRefusesAShallowClone(t *testing.T) {
	var out bytes.Buffer
	err := run(&out, ".", "docs/runs.md", "HEAD", fakeGit(t, "true"))
	if !errors.Is(err, errShallow) {
		t.Errorf("run error = %v, want errShallow", err)
	}
	if out.Len() != 0 {
		t.Errorf("run printed %q from a shallow clone", out.String())
	}
}
