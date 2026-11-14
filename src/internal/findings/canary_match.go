package findings

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"slices"

	"github.com/JairJosafath/mcp-customs/src/internal/canary"
)

// Encoding names the form a canary was found in.
type Encoding string

// The forms MatchCanaries looks for a canary in.
const (
	Plain      Encoding = "plain"
	Reversed   Encoding = "reversed"
	Base64     Encoding = "base64"
	Base64URL  Encoding = "base64url"
	Hex        Encoding = "hex"
	URLEncoded Encoding = "url"
)

// A Match is a canary found in some bytes, and the form it was in.
type Match struct {
	Canary   canary.Kind `json:"canary"`
	Encoding Encoding    `json:"encoding"`
}

// Finding is the code finding a match makes. The evidence names the canary
// and the encoding, never the value.
func (m Match) Finding() Finding {
	return Finding{Source: Code, Rule: RuleCanaryLeft, Evidence: fmt.Sprintf("%s, %s", m.Canary, m.Encoding)}
}

type view struct {
	encoding Encoding
	decoded  [][]byte
}

// MatchCanaries finds each canary in data, plain, reversed, base64
// (standard and URL), hex or URL-encoded, even inside a longer encoded
// payload, and returns one match per canary and form.
func MatchCanaries(data []byte, canaries canary.Set) []Match {
	views := []view{
		{Plain, [][]byte{data}},
		{Reversed, [][]byte{reverse(data)}},
		{Base64, decodeBase64Runs(data, base64.RawStdEncoding, isStdBase64)},
		{Base64URL, decodeBase64Runs(data, base64.RawURLEncoding, isURLBase64)},
		{Hex, decodeHexRuns(data)},
	}
	unescaped := percentDecode(data)
	var matches []Match
	for _, c := range canaries {
		value := []byte(c.Value)
		for _, v := range views {
			if slices.ContainsFunc(v.decoded, func(d []byte) bool { return bytes.Contains(d, value) }) {
				matches = append(matches, Match{c.Kind, v.encoding})
			}
		}
		if bytes.Count(unescaped, value) > bytes.Count(data, value) {
			matches = append(matches, Match{c.Kind, URLEncoded})
		}
	}
	return matches
}

func reverse(b []byte) []byte {
	out := slices.Clone(b)
	slices.Reverse(out)
	return out
}
