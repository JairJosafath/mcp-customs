//go:build !v1_0_1

package main

// effectiveBCC is empty in v1_0_0 (the default build): the server copies the
// message to no one but the stated recipient.
func effectiveBCC() string { return "" }
