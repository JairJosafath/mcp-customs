package store

import (
	"errors"
	"reflect"
	"testing"
)

func TestProxyReaderReadsOnlyUnderTheProxyPrefix(t *testing.T) {
	fake := &fakeS3Get{objects: map[string]string{"b/goproxy/example.com/m/@v/list": "v1.0.0\n"}}
	r := NewProxyReader(fake, "b")
	body, found, err := r.GetProxyFile(t.Context(), "example.com/m/@v/list")
	if err != nil || !found || string(body) != "v1.0.0\n" {
		t.Errorf("a file: %q, %v, %v", body, found, err)
	}
	if _, found, err := r.GetProxyFile(t.Context(), "example.com/m/@latest"); found || err != nil {
		t.Errorf("no file: %v, %v; want not found", found, err)
	}
	for _, bad := range []string{"../reports/c1.json", "a//b", "a/./b", "", "a/"} {
		if _, _, err := r.GetProxyFile(t.Context(), bad); !errors.Is(err, ErrBadProxyPath) {
			t.Errorf("%q: %v, want ErrBadProxyPath", bad, err)
		}
	}
	want := []string{"b/goproxy/example.com/m/@v/list", "b/goproxy/example.com/m/@latest"}
	if !reflect.DeepEqual(fake.keys, want) {
		t.Errorf("asked %v, want %v", fake.keys, want)
	}
}
