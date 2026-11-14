package basebump

import (
	"cmp"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// evr is a package's epoch, version and release.
type evr struct {
	Epoch string `xml:"epoch,attr"`
	Ver   string `xml:"ver,attr"`
	Rel   string `xml:"rel,attr"`
}

// String is the version as a pin names it: the epoch only when it isn't 0.
func (v evr) String() string {
	if v.Epoch == "" || v.Epoch == "0" {
		return v.Ver + "-" + v.Rel
	}
	return v.Epoch + ":" + v.Ver + "-" + v.Rel
}

// compare orders two versions the way rpm and dnf do.
func (v evr) compare(w evr) int {
	return cmp.Or(cmp.Compare(epoch(v.Epoch), epoch(w.Epoch)), vercmp(v.Ver, w.Ver), vercmp(v.Rel, w.Rel))
}

// epoch is an epoch's number; none, or a malformed one, counts as 0, as rpm counts it.
func epoch(s string) int {
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0
	}
	return n
}

// ErrNoPackage says the repository holds no build of a package.
var ErrNoPackage = errors.New("not in the repository")

// Newest reads a repository's primary.xml and returns the newest
// [epoch:]version-release of each named package built for arch or noarch.
func Newest(primary io.Reader, arch string, names []string) (map[string]string, error) {
	newest := map[string]evr{}
	for _, name := range names {
		newest[name] = evr{}
	}
	d := xml.NewDecoder(primary)
	for {
		tok, err := d.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("read primary.xml: %w", err)
		}
		start, ok := tok.(xml.StartElement)
		if !ok || start.Name.Local != "package" {
			continue
		}
		var p struct {
			Name    string `xml:"name"`
			Arch    string `xml:"arch"`
			Version evr    `xml:"version"`
		}
		if err := d.DecodeElement(&p, &start); err != nil {
			return nil, fmt.Errorf("read primary.xml: %w", err)
		}
		best, wanted := newest[p.Name]
		if wanted && (p.Arch == arch || p.Arch == "noarch") && (best.Ver == "" || p.Version.compare(best) > 0) {
			newest[p.Name] = p.Version
		}
	}
	out := make(map[string]string, len(names))
	for name, v := range newest {
		if v.Ver == "" {
			return nil, fmt.Errorf("package %s for %s: %w", name, arch, ErrNoPackage)
		}
		out[name] = v.String()
	}
	return out, nil
}

// vercmp is rpm's rpmvercmp: the strings split into runs of digits and of
// letters, compared run by run; digits beat letters, numbers compare as
// numbers, and the string with runs left over is the newer. Every other
// character only separates runs.
func vercmp(a, b string) int {
	isDigit := func(r rune) bool { return r >= '0' && r <= '9' }
	isAlpha := func(r rune) bool { return (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') }
	separator := func(r rune) bool { return !isDigit(r) && !isAlpha(r) }
	for {
		a, b = strings.TrimLeftFunc(a, separator), strings.TrimLeftFunc(b, separator)
		if a == "" || b == "" {
			return cmp.Compare(len(a), len(b))
		}
		class := isAlpha
		if isDigit(rune(a[0])) {
			class = isDigit
		}
		var ra, rb string
		ra, a = span(a, class)
		rb, b = span(b, class)
		if rb == "" {
			// Different kinds of run: digits are newer.
			if isDigit(rune(ra[0])) {
				return 1
			}
			return -1
		}
		if isDigit(rune(ra[0])) {
			ra, rb = strings.TrimLeft(ra, "0"), strings.TrimLeft(rb, "0")
			if c := cmp.Compare(len(ra), len(rb)); c != 0 {
				return c
			}
		}
		if c := strings.Compare(ra, rb); c != 0 {
			return c
		}
	}
}

// span splits s after its leading run of characters in class.
func span(s string, class func(rune) bool) (run, rest string) {
	i := strings.IndexFunc(s, func(r rune) bool { return !class(r) })
	if i < 0 {
		return s, ""
	}
	return s[:i], s[i:]
}
