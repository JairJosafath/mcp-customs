package sandbox

import (
	"encoding/base64"
	"testing"
)

func TestNewRunTokenIsThirtyTwoFreshRandomBytes(t *testing.T) {
	seen := map[string]bool{}
	for range 100 {
		tok, err := NewRunToken()
		if err != nil {
			t.Fatalf("NewRunToken: %v", err)
		}
		b, err := base64.RawURLEncoding.DecodeString(tok)
		if err != nil || len(b) != 32 {
			t.Fatalf("token %q decodes to %d bytes, %v; want 32", tok, len(b), err)
		}
		if seen[tok] {
			t.Fatalf("token %q made twice", tok)
		}
		seen[tok] = true
	}
}

func TestRunHookPayloadIsTheTokenAndCanariesAsJSON(t *testing.T) {
	got, err := encodeRunHookPayload(Launch{IdempotencyKey: "k", Token: "run-token", Canaries: []Canary{{Kind: "email", Value: "dev@example.com"}}})
	if err != nil {
		t.Fatalf("encodeRunHookPayload: %v", err)
	}
	want := `{"token":"run-token","canaries":[{"kind":"email","value":"dev@example.com"}]}`
	if got != want {
		t.Errorf("payload = %s, want %s", got, want)
	}
}
