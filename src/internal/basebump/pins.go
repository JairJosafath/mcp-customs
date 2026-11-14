// Package basebump moves sandbox/Dockerfile to another tag of Lambda's
// MicroVM base image: the tag, its digest, the Amazon Linux 2023 release the
// tag was built from, and the version of every package dnf installs, as that
// release's repository holds it. Parse and Rewrite work on the file's text;
// Source reads the public ECR gallery and the release's repository.
package basebump

import (
	"errors"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strings"
)

// Base is what pins the Dockerfile to one base image.
type Base struct {
	// Tag is the gallery tag, al2023-minimal.YYYY.MM.DD.HH.
	Tag string
	// Digest is the tag's manifest list, sha256:<64 hex>.
	Digest string
	// Release is the Amazon Linux 2023 release, 2023.N.YYYYMMDD.
	Release string
	// Packages maps each package dnf installs to its pinned
	// [epoch:]version-release.
	Packages map[string]string
}

var (
	fromRE    = regexp.MustCompile(`(?m)^FROM public\.ecr\.aws/lambda/microvms:(al2023-minimal\.[0-9.]+)@(sha256:[0-9a-f]{64})$`)
	releaseRE = regexp.MustCompile(`(?m)^ARG AL2023_RELEASE=(2023\.\d+\.\d{8})$`)
	installRE = regexp.MustCompile(`dnf install -y [^&]*`)
	// A pin is name-[epoch:]version-release; neither version nor release
	// holds a dash, so the last two dashes split it.
	pinRE  = regexp.MustCompile(`^([a-z][a-zA-Z0-9+._-]*)-((?:\d+:)?[0-9][a-zA-Z0-9._+~^]*-[0-9][a-zA-Z0-9._+~^]*)$`)
	wordRE = regexp.MustCompile(`\S+`)
	// What Rewrite accepts as a tag, a digest and a release.
	tagRE     = regexp.MustCompile(`^al2023-minimal\.[0-9.]+$`)
	digestRE  = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	releaseIs = regexp.MustCompile(`^2023\.\d+\.\d{8}$`)
)

// ErrNotPinned says the Dockerfile lacks a pin Parse needs.
var ErrNotPinned = errors.New("not pinned")

// Parse reads the base the Dockerfile is pinned to. It fails when the FROM,
// the release or a dnf install's package is not pinned.
func Parse(dockerfile string) (Base, error) {
	from := fromRE.FindStringSubmatch(dockerfile)
	if from == nil {
		return Base{}, fmt.Errorf("the FROM line, by tag and digest: %w", ErrNotPinned)
	}
	release := releaseRE.FindStringSubmatch(dockerfile)
	if release == nil {
		return Base{}, fmt.Errorf("ARG AL2023_RELEASE: %w", ErrNotPinned)
	}
	b := Base{Tag: from[1], Digest: from[2], Release: release[1], Packages: map[string]string{}}
	for _, install := range installRE.FindAllString(dockerfile, -1) {
		for _, word := range packageWords(install) {
			pin := pinRE.FindStringSubmatch(word)
			if pin == nil {
				return Base{}, fmt.Errorf("package %q: %w", word, ErrNotPinned)
			}
			b.Packages[pin[1]] = pin[2]
		}
	}
	if len(b.Packages) == 0 {
		return Base{}, fmt.Errorf("dnf install's packages: %w", ErrNotPinned)
	}
	return b, nil
}

// Names lists the packages, sorted.
func (b Base) Names() []string {
	return slices.Sorted(maps.Keys(b.Packages))
}

// packageWords are the words of a dnf install that name packages: not its
// options or the line continuations.
func packageWords(install string) []string {
	var words []string
	for _, word := range strings.Fields(strings.TrimPrefix(install, "dnf install -y")) {
		if word[0] >= 'a' && word[0] <= 'z' {
			words = append(words, word)
		}
	}
	return words
}

// Rewrite moves the Dockerfile to base `to`: every mention of the current
// tag, digest and release, and every package pin. `to` must name a version
// of every package the Dockerfile installs.
func Rewrite(dockerfile string, to Base) (string, error) {
	from, err := Parse(dockerfile)
	if err != nil {
		return "", err
	}
	if !tagRE.MatchString(to.Tag) || !digestRE.MatchString(to.Digest) || !releaseIs.MatchString(to.Release) {
		return "", fmt.Errorf("tag %q, digest %q, release %q: not a base", to.Tag, to.Digest, to.Release)
	}
	for _, name := range from.Names() {
		version, ok := to.Packages[name]
		if !ok || !pinRE.MatchString(name+"-"+version) {
			return "", fmt.Errorf("package %s: version %q: %w", name, version, ErrNotPinned)
		}
	}
	out := strings.NewReplacer(from.Tag, to.Tag, from.Digest, to.Digest, from.Release, to.Release).Replace(dockerfile)
	out = installRE.ReplaceAllStringFunc(out, func(install string) string {
		return wordRE.ReplaceAllStringFunc(install, func(word string) string {
			if pin := pinRE.FindStringSubmatch(word); pin != nil {
				return pin[1] + "-" + to.Packages[pin[1]]
			}
			return word
		})
	})
	return out, nil
}
