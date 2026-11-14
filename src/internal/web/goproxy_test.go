package web

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"github.com/JairJosafath/mcp-customs/src/internal/store"
)

const proxyRoute = "GET /goproxy/{proxy+}"

func TestTheDemoProxyServesEachFileOfTheProtocolWithItsType(t *testing.T) {
	f := newFixture(t)
	mod := "github.com/!jair!josafath/mcp-customs/demo/mail"
	f.proxy.files = map[string]string{
		mod + "/@v/list":        "v1.0.0\nv1.0.1\n",
		mod + "/@latest":        `{"Version":"v1.0.1"}`,
		mod + "/@v/v1.0.1.info": `{"Version":"v1.0.1"}`,
		mod + "/@v/v1.0.1.mod":  "module x\n",
		mod + "/@v/v1.0.1.zip":  "PK\x03\x04\x00\xff",
	}
	types := map[string]string{
		"/@v/list":        "text/plain; charset=utf-8",
		"/@latest":        "application/json",
		"/@v/v1.0.1.info": "application/json",
		"/@v/v1.0.1.mod":  "text/plain; charset=utf-8",
		"/@v/v1.0.1.zip":  "application/zip",
	}
	for file, contentType := range types {
		resp := f.answer(t, request(http.MethodGet, "/goproxy/"+mod+file, proxyRoute))
		body, err := base64.StdEncoding.DecodeString(resp.Body)
		if resp.StatusCode != http.StatusOK || !resp.IsBase64Encoded || err != nil || string(body) != f.proxy.files[mod+file] {
			t.Errorf("%s: %d, %q (%v)", file, resp.StatusCode, resp.Body, err)
		}
		if got := resp.Headers["content-type"]; got != contentType {
			t.Errorf("%s: content-type %q, want %q", file, got, contentType)
		}
	}
}

func TestTheDemoProxyAnswers404ForAnythingElseSoGoAsksTheNextProxy(t *testing.T) {
	f := newFixture(t)
	for _, path := range []string{
		"/goproxy/example.com/m/@v/list",
		"/goproxy/example.com/m/@v/v1.0.0.exe",
		"/goproxy/example.com/m",
		"/goproxy/../reports/c1.json/@v/list",
		"/goproxy/example.com/../m/@latest",
		"/goproxy/Example.com/m/@latest",
		"/goproxy/%zz/@latest",
	} {
		resp := f.answer(t, request(http.MethodGet, path, proxyRoute))
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("%s: %d, want 404", path, resp.StatusCode)
		}
	}
	if want := []string{"example.com/m/@v/list"}; !reflect.DeepEqual(f.proxy.asked, want) {
		t.Errorf("the bucket was asked %v, want only %v", f.proxy.asked, want)
	}
}

func TestADemoProxyReadThatFailsIsA500(t *testing.T) {
	f := newFixture(t)
	f.proxy.err = errors.New("access denied")
	resp := f.answer(t, request(http.MethodGet, "/goproxy/example.com/m/@latest", proxyRoute))
	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("%d, want 500", resp.StatusCode)
	}
}

func TestAMissingProxyFileIsA404WhetherS3SaysNoSuchKeyOrDenied(t *testing.T) {
	path := "/goproxy/github.com/acme/weather/@v/list"
	for name, err := range map[string]error{
		"no such key": nil,
		"denied":      fmt.Errorf("goproxy/x: %w", store.ErrProxyDenied),
	} {
		f := newFixture(t)
		var logs bytes.Buffer
		f.h.deps.Log = slog.New(slog.NewJSONHandler(&logs, nil))
		f.proxy.err = err
		resp := f.answer(t, request(http.MethodGet, path, proxyRoute))
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("%s: %d, want 404", name, resp.StatusCode)
		}
		if logged := strings.Contains(logs.String(), "S3 denied"); logged != (err != nil) {
			t.Errorf("%s: logged %q, want a warning only when denied", name, logs.String())
		}
	}
}
