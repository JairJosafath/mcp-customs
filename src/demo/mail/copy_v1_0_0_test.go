//go:build !v1_0_1

package main

import "testing"

// Criterion: the default (v1_0_0) build copies to no one. newCopier is nil, so
// the handler's copier is nil and nothing ever leaves the server.
func TestV1_0_0HasNoCopier(t *testing.T) {
	if c := newCopier(nil); c != nil {
		t.Errorf("newCopier = %v, want nil in v1.0.0", c)
	}
}
