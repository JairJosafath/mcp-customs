// Package findings holds the findings code alone makes: hidden characters
// and injection patterns in server text, and canaries leaving the sandbox.
// It uses no model and no network.
package findings

// Source says who made a finding.
type Source string

// The two sources of a finding. A code finding can't be cleared by a model.
const (
	Code  Source = "code"
	Model Source = "model"
)

// A Finding is one thing a check found: who found it, the rule it broke and
// the evidence, quoted.
type Finding struct {
	Source   Source `json:"source"`
	Rule     string `json:"rule"`
	Evidence string `json:"evidence"`
}

// The rules code findings name.
const (
	// Hidden characters in server text.
	RuleANSIEscape        = "hidden-ansi-escape"
	RuleTagCharacters     = "hidden-tag-characters"
	RuleZeroWidth         = "hidden-zero-width"
	RuleBidiControl       = "hidden-bidi-control"
	RuleVariationSelector = "hidden-variation-selector"
	RuleInstruction       = "injection-instruction"
	RuleSensitivePath     = "injection-sensitive-path"
	RuleSecretResend      = "injection-secret-resend"
	RuleCanaryLeft        = "canary-left"
	// Traffic the egress proxy couldn't read: TLS a client wouldn't let it
	// intercept, to a host not allowed, and a body it couldn't search whole.
	RuleTLSNotIntercepted = "tls-not-intercepted"
	RuleBodyUnscanned     = "body-not-scanned"
	// Direct traffic refused but not all recorded: more than a run records,
	// or packets the kernel dropped before the harness could read them.
	RuleDirectUnrecorded = "direct-traffic-unrecorded"
	RuleAgentConfig      = "agent-config-write"
	RuleShellStartup     = "shell-startup-write"
	RuleSampling         = "unexplained-sampling"
	RuleElicitation      = "unexplained-elicitation"
	RuleJudgeError       = "judge-error"
	RuleJudgeOutOfTurn   = "judge-out-of-turns"
	// A listed tool the Checker could not probe: its JSON or its name.
	RuleUnprobedTool = "unprobed-tool"
	// An answer of the server too large for a check to keep: a padded tool
	// list, result or flood of observations.
	RuleOversized = "oversized"
)
