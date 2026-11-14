package store

import (
	"errors"
	"reflect"
	"testing"

	"github.com/aws/smithy-go"
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

func TestAProxyReadS3DeniesIsErrProxyDenied(t *testing.T) {
	denied := &fakeS3Get{err: &smithy.GenericAPIError{Code: "AccessDenied", Message: "Access Denied"}}
	if _, found, err := NewProxyReader(denied, "b").GetProxyFile(t.Context(), "example.com/m/@latest"); found || !errors.Is(err, ErrProxyDenied) {
		t.Errorf("denied: %v, %v; want ErrProxyDenied", found, err)
	}
	failed := &fakeS3Get{err: &smithy.GenericAPIError{Code: "InternalError"}}
	if _, _, err := NewProxyReader(failed, "b").GetProxyFile(t.Context(), "example.com/m/@latest"); err == nil || errors.Is(err, ErrProxyDenied) {
		t.Errorf("another failure: %v, want an error other than ErrProxyDenied", err)
	}
}
