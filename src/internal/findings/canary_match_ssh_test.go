package findings

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/JairJosafath/mcp-customs/src/internal/canary"
)

// wrap breaks s into lines of width characters, each ended by eol, as
// coreutils base64 (76, "\n"), Python's encodebytes (76, "\n"), MIME
// (76, "\r\n") and xxd -p (60, "\n") do.
func wrap(s string, width int, eol string) string {
	var b strings.Builder
	for len(s) > width {
		b.WriteString(s[:width] + eol)
		s = s[width:]
	}
	b.WriteString(s + eol)
	return b.String()
}

func jsonString(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestMatchCanariesFindsTheSSHKeyInTheFormsItLeavesIn(t *testing.T) {
	set := canary.New()
	key := set.Get(canary.SSHPrivateKey)
	b64 := base64.StdEncoding.EncodeToString
	inJSON := jsonString(t, map[string]string{"city": "Amsterdam", "auth_context": key})
	reversed := []byte(key)
	slices.Reverse(reversed)
	tests := []struct {
		name string
		data string
		want Encoding
	}{
		{"whole block", "x" + key, Plain},
		{"trimmed", strings.TrimSpace(key), Plain},
		{"CRLF line endings", strings.ReplaceAll(key, "\n", "\r\n"), Plain},
		{"escaped in a JSON argument", inJSON, Plain},
		{"base64 of that JSON", b64([]byte(inJSON)), Base64},
		{"base64 wrapped at 76 with CRLF, as MIME", wrap(b64([]byte(key)), 76, "\r\n"), Base64},
		{"base64 wrapped at 76, as coreutils and Python's encodebytes", "body=" + wrap(b64([]byte("k="+key)), 76, "\n"), Base64},
		{"wrapped base64 escaped in JSON", jsonString(t, map[string]string{"d": wrap(b64([]byte(key)), 76, "\n")}), Base64},
		{"base64url", base64.RawURLEncoding.EncodeToString([]byte(strings.TrimSpace(key))), Base64URL},
		{"hex wrapped at 60, as xxd -p", wrap(hex.EncodeToString([]byte(key)), 60, "\n"), Hex},
		{"URL-encoded", "k=" + url.QueryEscape(key), URLEncoded},
		{"reversed", string(reversed), Reversed},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			want := Match{canary.SSHPrivateKey, tt.want}
			if got := MatchCanaries([]byte(tt.data), set); !slices.Contains(got, want) {
				t.Errorf("MatchCanaries = %+v, want it to contain %+v", got, want)
			}
		})
	}
}

func TestMatchCanariesFindsATokenSplitAcrossWrappedLines(t *testing.T) {
	set := canary.New()
	// The token takes bytes 40 to 80, across the break after byte 57 (76
	// columns) or 48 (64 columns).
	payload := []byte(strings.Repeat("a", 30) + `{"token":"` + set.Get(canary.GitHubToken) + `"}`)
	tests := []struct {
		name string
		data string
	}{
		{"LF", wrap(base64.StdEncoding.EncodeToString(payload), 76, "\n")},
		{"CRLF", wrap(base64.StdEncoding.EncodeToString(payload), 76, "\r\n")},
		{"wrapped at 64, as PEM", wrap(base64.StdEncoding.EncodeToString(payload), 64, "\n")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			want := Match{canary.GitHubToken, Base64}
			if got := MatchCanaries([]byte(tt.data), set); !slices.Contains(got, want) {
				t.Errorf("MatchCanaries = %+v, want it to contain %+v", got, want)
			}
		})
	}
}
