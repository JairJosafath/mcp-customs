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

// gallery serves testdata as the ECR gallery and AL2023's repository do:
// the tag's manifest list, its manifests and blobs by digest behind the
// token, the release's mirror list, repomd.xml and gzipped primary.xml.
// tamper changes a served file's bytes, by name.
func gallery(t *testing.T, tamper map[string]func([]byte) []byte) basebump.Source {
	t.Helper()
	var gz bytes.Buffer
	w := gzip.NewWriter(&gz)
	if _, err := w.Write(fixture(t, "primary.xml")); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(gz.Bytes())
	repomd := strings.Replace(string(fixture(t, "repomd.xml")), "{{primary.xml.gz}}", hex.EncodeToString(sum[:]), 1)
	files := map[string][]byte{
		"/token/":                              fixture(t, "token.json"),
		"/v2/lambda/microvms/manifests/" + tag: fixture(t, "manifest-list.json"),
		"/mirrors/2023.12.20261112/aarch64/mirror.list":         fixture(t, "mirror.list"),
		"/mirrors/guids/0d08b7/aarch64/repodata/repomd.xml":     []byte(repomd),
		"/mirrors/guids/0d08b7/aarch64/repodata/primary.xml.gz": gz.Bytes(),
	}
	names := map[string]string{
		"/v2/lambda/microvms/manifests/" + tag:                  "manifest-list.json",
		"/mirrors/guids/0d08b7/aarch64/repodata/primary.xml.gz": "primary.xml.gz",
	}
	for _, name := range []string{"manifest.json", "manifest-amd64.json"} {
		files["/v2/lambda/microvms/manifests/"+digestOf(fixture(t, name))] = fixture(t, name)
		names["/v2/lambda/microvms/manifests/"+digestOf(fixture(t, name))] = name
	}
	files["/v2/lambda/microvms/blobs/"+digestOf(fixture(t, "config.json"))] = fixture(t, "config.json")
	names["/v2/lambda/microvms/blobs/"+digestOf(fixture(t, "config.json"))] = "config.json"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, ok := files[r.URL.Path]
		if strings.HasPrefix(r.URL.Path, "/v2/") && r.Header.Get("Authorization") != "Bearer fixture-token" {
			ok = false
		}
		if !ok {
			http.NotFound(w, r)
			return
		}
		if f := tamper[names[r.URL.Path]]; f != nil {
			body = f(body)
		}
		_, _ = w.Write(body)
	}))
	t.Cleanup(server.Close)
	return basebump.Source{
		Client:     server.Client(),
		Gallery:    server.URL,
		Repository: "lambda/microvms",
		Mirrors:    server.URL + "/mirrors",
		Arch:       "aarch64",
	}
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
				"primary.xml.gz": func(b []byte) []byte { return append(b, 0) },
			},
			want: "not the sha256 checksum",
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
		})
	}
}
