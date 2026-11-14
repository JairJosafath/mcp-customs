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
	ObservedTruncated   = "truncated"
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
// request, and every kind the harness stopped recording, which the judge
// may explain but not clear. Each finding is made
// once, however often it was seen.
func FromObservations(observations []Observation, canaries canary.Set) []Finding {
	var found []Finding
	seen := map[Finding]bool{}
	add := func(f Finding) {
		if !seen[f] {
			seen[f] = true
			found = append(found, f)
		}
	}
	for _, o := range observations {
		switch o.Kind {
		case ObservedDNS, ObservedConnect, ObservedHTTP:
			for _, f := range networkFindings(o, canaries) {
				add(f)
			}
			for _, f := range unreadFindings(o) {
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
		case ObservedTruncated:
			add(Finding{Source: Code, Rule: RuleTruncated, Evidence: truncatedWhy(o.Detail)})
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

// unreadFindings are the findings of traffic the egress proxy couldn't
// read: a tunnel to a host not allowed whose TLS the client wouldn't let it
// intercept, as a client pinning its own roots does, a request, handshake
// or direct connection it couldn't search whole, or refused direct traffic
// it couldn't record all of, or stopped reading. What it couldn't read may
// hold a canary.
func unreadFindings(o Observation) []Finding {
	var d struct {
		Host        string `json:"host"`
		Address     string `json:"address"`
		Via         string `json:"via"`
		Intercepted bool   `json:"intercepted"`
		Allowed     bool   `json:"allowed"`
		Unscanned   string `json:"unscanned"`
		More        bool   `json:"more"`
		Dropped     int    `json:"dropped"`
		Stopped     string `json:"stopped"`
	}
	if json.Unmarshal(o.Detail, &d) != nil {
		return nil
	}
	var found []Finding
	direct := o.Kind == ObservedConnect && d.Via == "direct"
	if o.Kind == ObservedConnect && d.Via == "proxy" && !d.Intercepted && !d.Allowed {
		found = append(found, Finding{Source: Code, Rule: RuleTLSNotIntercepted, Evidence: "TLS to " + d.Host + " the proxy could not read"})
	}
	switch {
	case direct && d.Stopped != "":
		found = append(found, Finding{Source: Code, Rule: RuleDirectUnrecorded, Evidence: "the harness stopped reading refused packets (" + d.Stopped + "); any refused after may hold a canary"})
	case direct && d.Dropped > 0:
		found = append(found, Finding{Source: Code, Rule: RuleDirectUnrecorded, Evidence: "the kernel dropped refused packets before the harness could read them; any of them may hold a canary"})
	case direct && d.More:
		found = append(found, Finding{Source: Code, Rule: RuleDirectUnrecorded, Evidence: "more direct traffic was refused than a run records; only what held a canary was recorded after"})
	}
	if d.Unscanned != "" {
		where := d.Host
		if where == "" {
			where = d.Address
		}
		found = append(found, Finding{Source: Code, Rule: RuleBodyUnscanned, Evidence: where + ": " + d.Unscanned})
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

// truncatedWhy says which kind a truncated observation stopped recording,
// and why.
func truncatedWhy(raw json.RawMessage) string {
	var detail struct {
		Kind string `json:"kind"`
		Why  string `json:"why"`
	}
	if json.Unmarshal(raw, &detail) != nil || detail.Kind == "" {
		return "the harness stopped recording observations"
	}
	return "the harness stopped recording " + detail.Kind + " observations: " + detail.Why
}
