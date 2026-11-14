package findings

import (
	"encoding/hex"
	"encoding/json"
	"reflect"
	"testing"

	"github.com/JairJosafath/mcp-customs/src/internal/canary"
)

func observed(kind string, detail any) Observation {
	raw, err := json.Marshal(detail)
	if err != nil {
		panic(err)
	}
	return Observation{At: "2026-11-14T10:00:00Z", Kind: kind, Detail: raw}
}

func TestFromObservationsFindsWhatCodeCanTell(t *testing.T) {
	set := canary.New()
	key := set.Get(canary.GitHubToken)
	for name, tc := range map[string]struct {
		in   []Observation
		want []Finding
	}{
		"a canary the proxy found in a request": {
			[]Observation{observed(ObservedHTTP, map[string]any{
				"method": "POST", "host": "weather-cdn.example", "path": "/v1",
				"canaries": []Match{{Canary: canary.SSHPrivateKey, Encoding: Base64}},
			})},
			[]Finding{{Code, RuleCanaryLeft, "ssh-private-key, base64, to weather-cdn.example (http)"}},
		},
		"a canary in a DNS name": {
			[]Observation{observed(ObservedDNS, map[string]any{"host": hex.EncodeToString([]byte(key)) + ".evil.example"})},
			[]Finding{{Code, RuleCanaryLeft, "github-token, hex, to " + hex.EncodeToString([]byte(key)) + ".evil.example (dns)"}},
		},
		"a clean request": {
			[]Observation{observed(ObservedHTTP, map[string]any{"method": "GET", "host": "api.github.com", "path": "/user"})},
			nil,
		},
		"writes to startup and agent files, and an ordinary one": {
			[]Observation{
				observed(ObservedFile, map[string]any{"path": "/home/dev/.bashrc", "change": "modified"}),
				observed(ObservedFile, map[string]any{"path": "/home/dev/.cursor/mcp.json", "change": "created"}),
				observed(ObservedFile, map[string]any{"path": "/home/dev/project/CLAUDE.md", "change": "created"}),
				observed(ObservedFile, map[string]any{"path": "/home/dev/.config/fish/config.fish", "change": "created"}),
				observed(ObservedFile, map[string]any{"path": "/home/dev/notes/settings.json", "change": "created"}),
			},
			[]Finding{
				{Code, RuleShellStartup, "/home/dev/.bashrc"},
				{Code, RuleAgentConfig, "/home/dev/.cursor/mcp.json"},
				{Code, RuleAgentConfig, "/home/dev/project/CLAUDE.md"},
				{Code, RuleShellStartup, "/home/dev/.config/fish/config.fish"},
			},
		},
		"sampling and elicitation, each once": {
			[]Observation{
				observed(ObservedSampling, map[string]any{"method": "sampling/createMessage", "params": map[string]any{}}),
				observed(ObservedSampling, map[string]any{"method": "sampling/createMessage", "params": map[string]any{}}),
				observed(ObservedElicitation, map[string]any{}),
			},
			[]Finding{{Code, RuleSampling, "sampling/createMessage"}, {Code, RuleElicitation, "elicitation/create"}},
		},
		"TLS to a host not allowed that the client wouldn't let the proxy read": {
			[]Observation{
				observed(ObservedConnect, map[string]any{"host": "pinned.example", "port": 443, "via": "proxy", "intercepted": false, "allowed": false}),
				observed(ObservedConnect, map[string]any{"host": "registry.npmjs.org", "port": 443, "via": "proxy", "intercepted": false, "allowed": true}),
				observed(ObservedConnect, map[string]any{"host": "read.example", "port": 443, "via": "proxy", "intercepted": true, "allowed": false}),
				observed(ObservedConnect, map[string]any{"address": "203.0.113.7", "port": 443, "via": "direct", "refused": true}),
			},
			[]Finding{{Code, RuleTLSNotIntercepted, "TLS to pinned.example the proxy could not read"}},
		},
		"a request body the proxy couldn't search whole": {
			[]Observation{observed(ObservedHTTP, map[string]any{"method": "POST", "host": "big.example", "path": "/", "unscanned": "the body is over 8 MiB; only its first 8 MiB were searched"})},
			[]Finding{{Code, RuleBodyUnscanned, "big.example: the body is over 8 MiB; only its first 8 MiB were searched"}},
		},
		"a process, and a file with no path": {
			[]Observation{observed(ObservedProcess, map[string]any{"command": "sh"}), observed(ObservedFile, map[string]any{})},
			nil,
		},
	} {
		if got := FromObservations(tc.in, set); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%s: got %+v, want %+v", name, got, tc.want)
		}
	}
}
