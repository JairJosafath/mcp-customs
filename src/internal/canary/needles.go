package canary

import "strings"

// Needles are the strings that show this canary left, wherever it went.
// Most kinds are their value. An SSH key is its body lines but the first,
// which is the same for every ed25519 key: each of those lines carries key
// material, and survives the key being trimmed, given CRLF line endings or
// escaped into JSON.
func (c Canary) Needles() []string {
	if c.Kind != SSHPrivateKey {
		return []string{c.Value}
	}
	var body []string
	for line := range strings.Lines(c.Value) {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "-----") {
			body = append(body, line)
		}
	}
	if len(body) < 2 {
		return []string{c.Value}
	}
	return body[1:]
}
