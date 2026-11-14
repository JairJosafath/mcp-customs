package findings

import (
	"encoding/base64"
	"encoding/hex"
	"net/url"
	"slices"
	"testing"

	"github.com/JairJosafath/mcp-customs/src/internal/canary"
)

// testCanaries are fixed values whose base64 forms differ between the
// standard and URL alphabets.
var testCanaries = canary.Set{
	{Kind: canary.GitHubToken, Value: "ghp_R8b2Kq0LmZx7Vt4NcWy1Hs9Jd3Fp6Ga5Ue0Q1r2s"}, //nolint:gosec // a made-up canary, not a credential
	{Kind: canary.Password, Value: "p>?~>?~Tq9!x#Lz"},
	{Kind: canary.Email, Value: "sam.chen482913@proton.me"},
}

func TestMatchCanariesFindsEachEncoding(t *testing.T) {
	token := testCanaries[0].Value
	pass := testCanaries[1].Value
	mail := testCanaries[2].Value
	reversed := []byte(mail)
	slices.Reverse(reversed)
	tests := []struct {
		name string
		data string
		want Match
	}{
		{"plain", "POST /log HTTP/1.1\r\n\r\n{\"t\":\"" + token + "\"}", Match{canary.GitHubToken, Plain}},
		{"reversed", "q=" + string(reversed), Match{canary.Email, Reversed}},
		{"base64", "d=" + base64.StdEncoding.EncodeToString([]byte("pw="+pass+";")), Match{canary.Password, Base64}},
		{"base64 glued to a prefix", "x" + base64.StdEncoding.EncodeToString([]byte(token)), Match{canary.GitHubToken, Base64}},
		{"base64url", "/c/" + base64.RawURLEncoding.EncodeToString([]byte(pass)) + "/x", Match{canary.Password, Base64URL}},
		{"hex", "GET /?h=" + hex.EncodeToString([]byte("user="+mail)), Match{canary.Email, Hex}},
		{"hex, odd alignment", "GET /?h=a" + hex.EncodeToString([]byte(mail)), Match{canary.Email, Hex}},
		{"url-encoded", "GET /?e=" + url.QueryEscape(mail) + "&p=" + url.QueryEscape(pass), Match{canary.Password, URLEncoded}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := MatchCanaries([]byte(tt.data), testCanaries)
			if !slices.Contains(got, tt.want) {
				t.Errorf("MatchCanaries = %+v, want it to contain %+v", got, tt.want)
			}
		})
	}
}

func TestMatchCanariesReportsPlainOnlyOnce(t *testing.T) {
	got := MatchCanaries([]byte("email="+testCanaries[2].Value), testCanaries)
	want := []Match{{canary.Email, Plain}}
	if !slices.Equal(got, want) {
		t.Errorf("MatchCanaries = %+v, want %+v", got, want)
	}
}

func TestMatchCanariesFindsNothingInCleanTraffic(t *testing.T) {
	data := "GET /forecast?city=Amsterdam HTTP/1.1\r\nHost: api.weather.example\r\nAuthorization: Bearer ZXhhbXBsZQ==\r\n"
	if got := MatchCanaries([]byte(data), testCanaries); len(got) != 0 {
		t.Errorf("MatchCanaries = %+v, want none", got)
	}
}

func TestMatchCanariesFindsFreshSetsSSHKeyInBase64(t *testing.T) {
	set := canary.New()
	data := base64.StdEncoding.EncodeToString([]byte("file:" + set.Get(canary.SSHPrivateKey)))
	want := Match{canary.SSHPrivateKey, Base64}
	if got := MatchCanaries([]byte(data), set); !slices.Contains(got, want) {
		t.Errorf("MatchCanaries = %+v, want it to contain %+v", got, want)
	}
}

func TestMatchFindingNamesCanaryNotValue(t *testing.T) {
	got := Match{canary.GitHubToken, Hex}.Finding()
	want := Finding{Source: Code, Rule: RuleCanaryLeft, Evidence: "github-token, hex"}
	if got != want {
		t.Errorf("Finding = %+v, want %+v", got, want)
	}
}
