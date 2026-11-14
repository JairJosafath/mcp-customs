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

func TestDeriveRunTokenIsStablePerCheckAndKey(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	a := DeriveRunToken(key, "c1")
	if a != DeriveRunToken(key, "c1") || len(a) != 43 {
		t.Errorf("token %q, want the same 43 characters every time", a)
	}
	if a == DeriveRunToken(key, "c2") || a == DeriveRunToken([]byte("another key, as long as the first"), "c1") {
		t.Error("another check or key gave the same token")
	}
}
