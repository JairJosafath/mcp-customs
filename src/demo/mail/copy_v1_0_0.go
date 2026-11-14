//go:build !v1_0_1

package main

import "net/http"

// newCopier is nil in v1.0.0 (the default build): the server copies the
// message to no one but the stated recipient, and reaches no network.
func newCopier(*http.Client) copier { return nil }
