package basebump

import (
	"errors"
	"strings"
	"testing"
)

func TestVercmpOrdersVersionsAsRpmDoes(t *testing.T) {
	tests := []struct {
		a, b string
		want int
	}{
		{"1.0", "1.0", 0},
		{"1.10", "1.9", 1},
		{"amzn2023.0.10", "amzn2023.0.9", 1},
		{"1.0.1", "1.0", 1},
		{"1.0a", "1.0", 1},
		{"1.01", "1.1", 0},
		{"1.a", "1.1", -1},
		{"2.0_1", "2.0.1", 0},
	}
	for _, tt := range tests {
		if got := vercmp(tt.a, tt.b); got != tt.want {
			t.Errorf("vercmp(%q, %q) = %d, want %d", tt.a, tt.b, got, tt.want)
		}
		if got := vercmp(tt.b, tt.a); got != -tt.want {
			t.Errorf("vercmp(%q, %q) = %d, want %d", tt.b, tt.a, got, -tt.want)
		}
	}
}

const primary = `<metadata xmlns="http://linux.duke.edu/metadata/common">
<package><name>make</name><arch>aarch64</arch><version epoch="1" ver="4.3" rel="5.amzn2023.0.2"/></package>
<package><name>make</name><arch>aarch64</arch><version epoch="0" ver="4.4" rel="1.amzn2023"/></package>
<package><name>make</name><arch>x86_64</arch><version epoch="1" ver="4.5" rel="1.amzn2023"/></package>
</metadata>`

func TestNewestTakesTheHighestEpochForTheArch(t *testing.T) {
	got, err := Newest(strings.NewReader(primary), "aarch64", []string{"make"})
	if err != nil {
		t.Fatal(err)
	}
	if got["make"] != "1:4.3-5.amzn2023.0.2" {
		t.Errorf("make = %q", got["make"])
	}
}

func TestNewestFailsOnAPackageTheRepositoryLacks(t *testing.T) {
	_, err := Newest(strings.NewReader(primary), "aarch64", []string{"make", "gcc"})
	if !errors.Is(err, ErrNoPackage) || !strings.Contains(err.Error(), "gcc") {
		t.Errorf("Newest: %v, want ErrNoPackage for gcc", err)
	}
}

const dockerfile = `FROM public.ecr.aws/lambda/microvms:al2023-minimal.2026.11.05.18@sha256:3e45d46e969eb0d34ea954aff12747e15ca3f4a594788812c7218445777fa4bc
ARG AL2023_RELEASE=2023.12.20261102
RUN dnf install -y --setopt=install_weak_deps=False tar-2:1.34-1.amzn2023.0.4 \
      git-2.50.1-1.amzn2023.0.1 && dnf clean all
`

func TestParseReadsTheBase(t *testing.T) {
	b, err := Parse(dockerfile)
	if err != nil {
		t.Fatal(err)
	}
	if b.Tag != "al2023-minimal.2026.11.05.18" || b.Release != "2023.12.20261102" ||
		b.Packages["tar"] != "2:1.34-1.amzn2023.0.4" || b.Packages["git"] != "2.50.1-1.amzn2023.0.1" || len(b.Packages) != 2 {
		t.Errorf("Parse = %+v", b)
	}
}

func TestParseFailsOnAnUnpinnedPackage(t *testing.T) {
	_, err := Parse(strings.Replace(dockerfile, "git-2.50.1-1.amzn2023.0.1", "git", 1))
	if !errors.Is(err, ErrNotPinned) {
		t.Errorf("Parse: %v, want ErrNotPinned", err)
	}
}

func TestRewriteNeedsAVersionOfEveryPackage(t *testing.T) {
	to := Base{
		Tag:      "al2023-minimal.2026.11.12.03",
		Digest:   "sha256:" + strings.Repeat("a", 64),
		Release:  "2023.12.20261112",
		Packages: map[string]string{"tar": "2:1.35-1.amzn2023.0.1"},
	}
	if _, err := Rewrite(dockerfile, to); !errors.Is(err, ErrNotPinned) {
		t.Errorf("Rewrite: %v, want ErrNotPinned", err)
	}
	to.Packages["git"] = "2.51.0-1.amzn2023.0.1"
	got, err := Rewrite(dockerfile, to)
	if err != nil {
		t.Fatal(err)
	}
	after, err := Parse(got)
	if err != nil {
		t.Fatal(err)
	}
	if after.Tag != to.Tag || after.Digest != to.Digest || after.Release != to.Release ||
		after.Packages["git"] != to.Packages["git"] || after.Packages["tar"] != to.Packages["tar"] {
		t.Errorf("Rewrite gave %+v", after)
	}
	to.Digest = "sha256:short"
	if _, err := Rewrite(dockerfile, to); err == nil {
		t.Error("Rewrite took a malformed digest")
	}
}
