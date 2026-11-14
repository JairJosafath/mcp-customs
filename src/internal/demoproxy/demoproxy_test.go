package demoproxy

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/mod/module"
	modzip "golang.org/x/mod/zip"
)

// srcRoot is the src module's directory, which holds the demos.
var srcRoot = os.DirFS("../..")

// files are the proxy's files with the mail demo at version and the
// weather demo at v1.0.0.
func files(t *testing.T, version string) map[string][]byte {
	t.Helper()
	f, err := Files(srcRoot, map[string]string{"mail": version, "weather": "v1.0.0"})
	if err != nil {
		t.Fatal(err)
	}
	return f
}

// escaped is path as the proxy protocol has it.
func escaped(t *testing.T, path string) string {
	t.Helper()
	e, err := module.EscapePath(path)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

// unzip is the files of a module zip, by their path inside the module.
func unzip(t *testing.T, mod module.Version, data []byte) map[string]string {
	t.Helper()
	r, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	prefix := mod.Path + "@" + mod.Version + "/"
	for _, f := range r.File {
		name, ok := strings.CutPrefix(f.Name, prefix)
		if !ok {
			t.Fatalf("%s is outside %s", f.Name, prefix)
		}
		rc, err := f.Open()
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(rc)
		_ = rc.Close()
		if err != nil {
			t.Fatal(err)
		}
		out[name] = string(body)
	}
	return out
}

func TestTheProxyFilesFollowTheModuleProxyProtocolAndXModZip(t *testing.T) {
	got := files(t, "v1.0.1")
	mail, weather := ModulePrefix+"/mail", ModulePrefix+"/weather"
	lists := map[string]string{mail: "v1.0.0\nv1.0.1\n", weather: "v1.0.0\n"}
	latest := map[string]string{mail: "v1.0.1", weather: "v1.0.0"}
	for path, list := range lists {
		root := escaped(t, path)
		if string(got[root+"/@v/list"]) != list {
			t.Errorf("%s list %q, want %q", path, got[root+"/@v/list"], list)
		}
		var at struct{ Version, Time string }
		if err := json.Unmarshal(got[root+"/@latest"], &at); err != nil || at.Version != latest[path] || at.Time == "" {
			t.Errorf("%s @latest %s (%v), want %s with a time", path, got[root+"/@latest"], err, latest[path])
		}
		for v := range strings.FieldsSeq(list) {
			mod := module.Version{Path: path, Version: v}
			var info struct{ Version string }
			if err := json.Unmarshal(got[root+"/@v/"+v+".info"], &info); err != nil || info.Version != v {
				t.Errorf("%s .info %s (%v)", mod, got[root+"/@v/"+v+".info"], err)
			}
			zipPath := filepath.Join(t.TempDir(), v+".zip")
			if err := os.WriteFile(zipPath, got[root+"/@v/"+v+".zip"], 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := modzip.CheckZip(mod, zipPath); err != nil {
				t.Errorf("%s zip: %v", mod, err)
			}
			inZip := unzip(t, mod, got[root+"/@v/"+v+".zip"])
			if want := "module " + path + "\n\ngo 1.26\n"; string(got[root+"/@v/"+v+".mod"]) != want || inZip["go.mod"] != want {
				t.Errorf("%s .mod %q and zip go.mod %q, want %q", mod, got[root+"/@v/"+v+".mod"], inZip["go.mod"], want)
			}
		}
	}
	if len(got) != 2*2+3*3 {
		t.Errorf("%d files, want a list and @latest a module and three files a release", len(got))
	}
}

func TestEachReleaseIsItsModulesDefaultBuildWithNoBuildTag(t *testing.T) {
	cases := []struct {
		version, has, hasNot string
	}{
		{"v1.0.0", "copy_v1_0_0.go", "copy_v1_0_1.go"},
		{"v1.0.1", "copy_v1_0_1.go", "copy_v1_0_0.go"},
	}
	for _, c := range cases {
		t.Run(c.version, func(t *testing.T) {
			mod := module.Version{Path: ModulePrefix + "/mail", Version: c.version}
			src := unzip(t, mod, files(t, c.version)[escaped(t, mod.Path)+"/@v/"+c.version+".zip"])
			if _, ok := src[c.has]; !ok {
				t.Errorf("the zip has no %s", c.has)
			}
			if _, ok := src[c.hasNot]; ok {
				t.Errorf("the zip has %s", c.hasNot)
			}
			if _, ok := src["mail_test.go"]; ok {
				t.Error("the zip has the demo's tests")
			}
			if !strings.Contains(src["internal/mcp/mcp.go"], "package mcp") {
				t.Error("the zip has no internal/mcp")
			}
			for name, body := range src {
				if strings.Contains(body, "//go:build") || strings.Contains(body, "mcp-customs/src/") {
					t.Errorf("%s keeps a build line or an import of the src module", name)
				}
			}
			if !strings.Contains(src["mail.go"], `"`+mod.Path+`/internal/mcp"`) {
				t.Error("mail.go does not import the module's own mcp package")
			}
		})
	}
}

func TestPublishingAnEarlierVersionLeavesTheLaterOnesOff(t *testing.T) {
	got := files(t, "v1.0.0")
	root := escaped(t, ModulePrefix+"/mail")
	if _, ok := got[root+"/@v/v1.0.1.zip"]; ok {
		t.Error("v1.0.0's files hold v1.0.1")
	}
	if l := string(got[root+"/@v/list"]); l != "v1.0.0\n" {
		t.Errorf("list %q, want v1.0.0 alone", l)
	}
}

func TestAVersionOrDemoThereIsNoneOfIsRefused(t *testing.T) {
	cases := []struct {
		versions map[string]string
		want     error
	}{
		{map[string]string{"mail": "v1.0.2"}, ErrUnknownVersion},
		{map[string]string{"mail": "1.0.1"}, ErrUnknownVersion},
		{map[string]string{"mail": ""}, ErrUnknownVersion},
		{map[string]string{"weather": "v1.0.1"}, ErrUnknownVersion},
		{map[string]string{"mail": "v1.0.0", "calendar": "v1.0.0"}, ErrUnknownDemo},
	}
	for _, c := range cases {
		if _, err := Files(srcRoot, c.versions); !errors.Is(err, c.want) {
			t.Errorf("%v: %v, want %v", c.versions, err, c.want)
		}
	}
}

func TestADemoNotNamedIsNotPublished(t *testing.T) {
	got, err := Files(srcRoot, map[string]string{"weather": "v1.0.0"})
	if err != nil {
		t.Fatal(err)
	}
	for name := range got {
		if strings.Contains(name, "/demo/mail/") {
			t.Errorf("%s is published, though mail is not named", name)
		}
	}
	if len(got) != 5 {
		t.Errorf("%d files, want weather's five", len(got))
	}
}

func TestTheVersionsAreOneJSONObjectOfStrings(t *testing.T) {
	got, err := ParseVersions([]byte(`{"mail": "v1.0.1", "weather": "v1.0.0"}` + "\n"))
	if err != nil || len(got) != 2 || got["mail"] != "v1.0.1" || got["weather"] != "v1.0.0" {
		t.Errorf("%v, %v", got, err)
	}
	for _, bad := range []string{``, `null`, `[]`, `{"mail": 1}`, `{"mail": "v1.0.0"} {}`, `"v1.0.1"`} {
		if _, err := ParseVersions([]byte(bad)); !errors.Is(err, ErrBadVersions) {
			t.Errorf("%q: %v, want ErrBadVersions", bad, err)
		}
	}
}

func TestABuildLineNamingAnythingButVersionsIsRefused(t *testing.T) {
	cases := []struct {
		name, body string
		keep       bool
		err        bool
	}{
		{"no line", "package main\n", true, false},
		{"its version", "//go:build v1_0_1\n\npackage main\n", true, false},
		{"another version", "//go:build v1_0_1\n\npackage main\n", false, false},
		{"not that version", "//go:build !v1_0_1\n\npackage main\n", false, false},
		{"an OS", "//go:build linux\n\npackage main\n", false, true},
		{"a version and an OS", "//go:build v1_0_1 && linux\n\npackage main\n", false, true},
	}
	tags := map[string]string{"another version": "v1_0_0", "not that version": "v1_0_1"}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tag, ok := tags[c.name]
			if !ok {
				tag = "v1_0_1"
			}
			body, keep, err := forVersion([]byte(c.body), tag)
			if (err != nil) != c.err || (err == nil && keep != c.keep) {
				t.Fatalf("keep %v, %v; want keep %v, error %v", keep, err, c.keep, c.err)
			}
			if keep && strings.Contains(string(body), "//go:build") {
				t.Errorf("%q keeps its build line", body)
			}
		})
	}
}

func TestADemoImportingAModuleIsRefused(t *testing.T) {
	body := []byte("package main\n\nimport \"golang.org/x/net/html\"\n")
	if err := standardOrOwn(body, ModulePrefix+"/mail"); !errors.Is(err, ErrSource) {
		t.Errorf("%v, want ErrSource", err)
	}
	own := []byte("package main\n\nimport (\n\t\"fmt\"\n\t\"" + ModulePrefix + "/mail/internal/mcp\"\n)\n")
	if err := standardOrOwn(own, ModulePrefix+"/mail"); err != nil {
		t.Errorf("own and standard imports: %v", err)
	}
}

func TestAProxyListIsHTTPSURLsOnly(t *testing.T) {
	cases := []struct {
		list string
		want []string
	}{
		{"https://a.example/goproxy,https://proxy.golang.org", []string{"https://a.example/goproxy", "https://proxy.golang.org"}},
		{"https://proxy.golang.org", []string{"https://proxy.golang.org"}},
		{"https://a.example,direct", nil},
		{"off", nil},
		{"http://a.example", nil},
		{"https://a.example?x=1", nil},
		{"https://u@a.example", nil},
		{"https://a.example,", nil},
	}
	for _, c := range cases {
		got, err := SplitProxyList(c.list)
		if c.want == nil {
			if !errors.Is(err, ErrBadProxy) {
				t.Errorf("%q: %v, want ErrBadProxy", c.list, err)
			}
			continue
		}
		if err != nil || strings.Join(got, " ") != strings.Join(c.want, " ") {
			t.Errorf("%q: %v, %v; want %v", c.list, got, err, c.want)
		}
	}
}
