package findings

import (
	"encoding/json"
	"fmt"
	"path"
	"slices"
	"strings"

	"github.com/JairJosafath/mcp-customs/src/internal/canary"
)

// An Observation is one thing the harness saw the server under test do, as
// docs/contracts.md ("Harness API") shapes it: its kind and its detail.
type Observation struct {
	At     string          `json:"at"`
	Kind   string          `json:"kind"`
	Detail json.RawMessage `json:"detail"`
}

// The observation kinds the harness reports.
const (
	ObservedDNS         = "dns"
	ObservedConnect     = "connect"
	ObservedHTTP        = "http"
	ObservedFile        = "file"
	ObservedSampling    = "sampling"
	ObservedElicitation = "elicitation"
	ObservedProcess     = "process"
)

// agentConfigs are files an agent reads its servers or instructions from:
// a server that writes one adds itself, or its instructions, to the agent.
var agentConfigs = []string{
	"claude_desktop_config.json", ".claude.json", "CLAUDE.md", "AGENTS.md",
	"mcp.json", ".mcp.json", "settings.json", "settings.local.json",
	".cursorrules", "mcp_config.json", "config.yaml", "config.json",
}

// agentDirs are the directories agents keep those files in; a file in one
// counts only when its name is in agentConfigs, except CLAUDE.md and
// AGENTS.md, which count anywhere.
var agentDirs = []string{
	".claude", ".cursor", ".vscode", ".codeium", ".continue", ".gemini",
	".codex", ".windsurf", "Claude", ".aws/amazonq", ".kiro",
}

// shellStartups are files a shell runs at start: a write to one runs code
// in every later shell.
var shellStartups = []string{
	".bashrc", ".bash_profile", ".bash_login", ".bash_logout", ".profile",
	".zshrc", ".zprofile", ".zshenv", ".zlogin", ".config/fish/config.fish",
}

// FromObservations makes the code findings of what the server was seen
// doing: a canary in any network observation, a write to an agent's
// config or a shell's startup file, and every sampling or elicitation
// request, which the judge may explain but not clear. Each finding is made
// once, however often it was seen.
func FromObservations(observations []Observation, canaries canary.Set) []Finding {
	var found []Finding
	add := func(f Finding) {
		if !slices.Contains(found, f) {
			found = append(found, f)
		}
	}
	for _, o := range observations {
		switch o.Kind {
		case ObservedDNS, ObservedConnect, ObservedHTTP:
			for _, f := range networkFindings(o, canaries) {
				add(f)
			}
		case ObservedFile:
			if f, ok := fileFinding(o.Detail); ok {
				add(f)
			}
		case ObservedSampling:
			add(Finding{Source: Code, Rule: RuleSampling, Evidence: requestMethod(o.Detail, "sampling/createMessage")})
		case ObservedElicitation:
			add(Finding{Source: Code, Rule: RuleElicitation, Evidence: requestMethod(o.Detail, "elicitation/create")})
		}
	}
	return found
}

// networkFindings are the canaries in a network observation: those the
// egress proxy found in a request, and any in the observation itself, such
// as a key smuggled out in a DNS name or a URL.
func networkFindings(o Observation, canaries canary.Set) []Finding {
	var detail struct {
		Host     string  `json:"host"`
		Canaries []Match `json:"canaries"`
	}
	_ = json.Unmarshal(o.Detail, &detail)
	matches := append(slices.Clone(detail.Canaries), MatchCanaries(o.Detail, canaries)...)
	found := make([]Finding, 0, len(matches))
	for _, m := range matches {
		f := m.Finding()
		if detail.Host != "" {
			f.Evidence = fmt.Sprintf("%s, to %s (%s)", f.Evidence, detail.Host, o.Kind)
		}
		found = append(found, f)
	}
	return found
}

// fileFinding is the finding of a file write, if the file is an agent's
// config or a shell's startup file.
func fileFinding(raw json.RawMessage) (Finding, bool) {
	var detail struct {
		Path string `json:"path"`
	}
	if json.Unmarshal(raw, &detail) != nil || detail.Path == "" {
		return Finding{}, false
	}
	p := path.Clean(detail.Path)
	switch {
	case isShellStartup(p):
		return Finding{Source: Code, Rule: RuleShellStartup, Evidence: p}, true
	case isAgentConfig(p):
		return Finding{Source: Code, Rule: RuleAgentConfig, Evidence: p}, true
	}
	return Finding{}, false
}

func isShellStartup(p string) bool {
	return slices.ContainsFunc(shellStartups, func(s string) bool { return p == s || strings.HasSuffix(p, "/"+s) })
}

func isAgentConfig(p string) bool {
	base := path.Base(p)
	if base == "CLAUDE.md" || base == "AGENTS.md" || base == "claude_desktop_config.json" || base == ".claude.json" {
		return true
	}
	if !slices.Contains(agentConfigs, base) {
		return false
	}
	return slices.ContainsFunc(agentDirs, func(d string) bool { return strings.Contains(p, "/"+d+"/") || strings.HasPrefix(p, d+"/") })
}

// requestMethod names the request a sampling or elicitation observation
// recorded, or fallback when it names none.
func requestMethod(raw json.RawMessage, fallback string) string {
	var detail struct {
		Method string `json:"method"`
	}
	if json.Unmarshal(raw, &detail) != nil || detail.Method == "" {
		return fallback
	}
	return detail.Method
}
