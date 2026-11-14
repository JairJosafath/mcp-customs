package main

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/JairJosafath/mcp-customs/src/internal/basebump"
)

const tag = "al2023-minimal.2026.11.12.03"

// fixture reads a file in testdata.
func fixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func digestOf(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// gallery serves testdata over https as the ECR gallery and AL2023's
// repository do: the tag's manifest list, its manifests and blobs by digest
// behind the token (a blob through a redirect, as the gallery's CDN does),
// the release's mirror list, repomd.xml and gzipped primary.xml. tamper
// changes a file's bytes, by name, before it is served (primary.xml before
// it is gzipped and summed); {{host}} in what it returns becomes the
// server's own host.
func gallery(t *testing.T, tamper map[string]func([]byte) []byte) basebump.Source {
	t.Helper()
	read := func(name string) []byte {
		data := fixture(t, name)
		if f := tamper[name]; f != nil {
			data = f(data)
		}
		return data
	}
	var gz bytes.Buffer
	w := gzip.NewWriter(&gz)
	if _, err := w.Write(read("primary.xml")); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(gz.Bytes())
	repomd := bytes.Replace(read("repomd.xml"), []byte("{{primary.xml.gz}}"), []byte(hex.EncodeToString(sum[:])), 1)
	config := digestOf(fixture(t, "config.json"))
	files := map[string][]byte{
		"/token/":                              read("token.json"),
		"/v2/lambda/microvms/manifests/" + tag: read("manifest-list.json"),
		"/cdn/" + config:                       read("config.json"),
		"/mirrors/2023.12.20261112/aarch64/mirror.list":         read("mirror.list"),
		"/mirrors/guids/0d08b7/aarch64/repodata/repomd.xml":     repomd,
		"/mirrors/guids/0d08b7/aarch64/repodata/primary.xml.gz": gz.Bytes(),
	}
	for _, name := range []string{"manifest.json", "manifest-amd64.json"} {
		files["/v2/lambda/microvms/manifests/"+digestOf(fixture(t, name))] = read(name)
	}
	var host []byte // the server's, once it listens
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/v2/") && r.Header.Get("Authorization") != "Bearer fixture-token" {
			http.NotFound(w, r)
			return
		}
		if r.URL.Path == "/redirect/repodata/repomd.xml" {
			http.Redirect(w, r, "/mirrors/guids/0d08b7/aarch64/repodata/repomd.xml", http.StatusTemporaryRedirect)
			return
		}
		if r.URL.Path == "/v2/lambda/microvms/blobs/"+config {
			http.Redirect(w, r, "/cdn/"+config, http.StatusTemporaryRedirect)
			return
		}
		body, ok := files[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(bytes.ReplaceAll(body, []byte("{{host}}"), host))
	}))
	t.Cleanup(server.Close)
	host = []byte(server.Listener.Addr().String())
	return basebump.Source{
		Client:      server.Client(),
		Gallery:     server.URL,
		Repository:  "lambda/microvms",
		Mirrors:     server.URL + "/mirrors",
		Arch:        "aarch64",
		MirrorHosts: []string{server.Listener.Addr().String()},
	}
}

// elsewhere is another https server, which counts the requests it gets.
func elsewhere(t *testing.T) (url string, hits *atomic.Int32) {
	t.Helper()
	hits = &atomic.Int32{}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		_, _ = w.Write([]byte("<repomd/>"))
	}))
	t.Cleanup(server.Close)
	return server.URL, hits
}

// dockerfile copies testdata/Dockerfile somewhere bump may rewrite it.
func dockerfile(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "Dockerfile")
	if err := os.WriteFile(path, fixture(t, "Dockerfile"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestBumpRewritesTheTagDigestReleaseAndPinsFromTheGalleryAndRepository(t *testing.T) {
	path := dockerfile(t)
	var out bytes.Buffer
	if err := bump(t.Context(), gallery(t, nil), path, []string{tag}, &out); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if want := fixture(t, "Dockerfile.want"); !bytes.Equal(got, want) {
		t.Errorf("Dockerfile:\n%s\nwant:\n%s", got, want)
	}
	if want := fixture(t, "bump.out"); out.String() != string(want) {
		t.Errorf("output:\n%s\nwant:\n%s", out.String(), want)
	}
}

func TestBumpLeavesTheDockerfileAsItWasOnAnyError(t *testing.T) {
	other, hits := elsewhere(t)
	mirrorList := func(line string) map[string]func([]byte) []byte {
		return map[string]func([]byte) []byte{"mirror.list": func([]byte) []byte { return []byte(line + "\n") }}
	}
	tests := map[string]struct {
		args   []string
		tamper map[string]func([]byte) []byte
		want   string
	}{
		"no tag":                  {args: nil, want: "name one tag"},
		"a tag the gallery lacks": {args: []string{"al2023-minimal.2000.01.01.00"}, want: "404"},
		"a manifest that is not its digest": {
			args:   []string{tag},
			tamper: map[string]func([]byte) []byte{"manifest.json": func(b []byte) []byte { return append(b, ' ') }},
			want:   "the gallery sent",
		},
		"a tag without an arm64 image": {
			args: []string{tag},
			tamper: map[string]func([]byte) []byte{
				"manifest-list.json": func(b []byte) []byte {
					return bytes.Replace(b, []byte(`"arm64"`), []byte(`"arm"`), 1)
				},
			},
			want: "no linux/arm64 image",
		},
		"a config that is not its digest": {
			args: []string{tag},
			tamper: map[string]func([]byte) []byte{
				"config.json": func(b []byte) []byte { return bytes.ReplaceAll(b, []byte("ADD "), []byte("COPY ")) },
			},
			want: "the gallery sent",
		},
		"a package list that is not repomd.xml's checksum": {
			args: []string{tag},
			tamper: map[string]func([]byte) []byte{
				"repomd.xml": func(b []byte) []byte {
					return bytes.Replace(b, []byte("{{primary.xml.gz}}"), bytes.Repeat([]byte("0"), 64), 1)
				},
			},
			want: "not the sha256 checksum",
		},
		"a package the release lacks": {
			args: []string{tag},
			tamper: map[string]func([]byte) []byte{
				"primary.xml": func(b []byte) []byte {
					return bytes.ReplaceAll(b, []byte("<name>git</name>"), []byte("<name>git-lfs</name>"))
				},
			},
			want: "package git for aarch64: not in the repository",
		},
		"a mirror list naming another host": {args: []string{tag}, tamper: mirrorList(other + "/"), want: "not an AL2023 mirror host"},
		"a mirror list naming plain http":   {args: []string{tag}, tamper: mirrorList("http://{{host}}/mirrors/guids/0d08b7/aarch64/"), want: "not https"},
		"a mirror list naming a redirect":   {args: []string{tag}, tamper: mirrorList("https://{{host}}/redirect/"), want: "a redirect to"},
		"a repomd.xml naming another host": {
			args: []string{tag},
			tamper: map[string]func([]byte) []byte{
				"repomd.xml": func(b []byte) []byte {
					return bytes.Replace(b, []byte("repodata/primary.xml.gz"), []byte(other+"/primary.xml.gz"), 1)
				},
			},
			want: "not an AL2023 mirror host",
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			path := dockerfile(t)
			err := bump(t.Context(), gallery(t, tt.tamper), path, tt.args, &bytes.Buffer{})
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("bump: %v, want an error saying %q", err, tt.want)
			}
			got, _ := os.ReadFile(path)
			if !bytes.Equal(got, fixture(t, "Dockerfile")) {
				t.Errorf("the Dockerfile changed:\n%s", got)
			}
			if entries, _ := os.ReadDir(filepath.Dir(path)); len(entries) != 1 {
				t.Errorf("bump left %d files beside the Dockerfile", len(entries)-1)
			}
		})
	}
	if n := hits.Load(); n != 0 {
		t.Errorf("the other host got %d requests", n)
	}
}
