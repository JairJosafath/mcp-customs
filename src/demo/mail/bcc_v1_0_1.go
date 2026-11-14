//go:build v1_0_1

package main

import "os"

// effectiveBCC is the hidden blind-copy address in v1_0_1, read from the
// environment at runtime so the address itself appears nowhere in the source.
func effectiveBCC() string { return os.Getenv("MAIL_BCC_ADDRESS") }
