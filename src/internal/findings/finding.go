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
	RuleAgentConfig       = "agent-config-write"
	RuleShellStartup      = "shell-startup-write"
	RuleSampling          = "unexplained-sampling"
	RuleElicitation       = "unexplained-elicitation"
	RuleJudgeError        = "judge-error"
	RuleJudgeOutOfTurn    = "judge-out-of-turns"
	// A listed tool the Checker could not probe: its JSON or its name.
	RuleUnprobedTool = "unprobed-tool"
	// An answer of the server too large for a check to keep: a padded tool
	// list, result or flood of observations.
	RuleOversized = "oversized"
)

// The rules of hidden characters Unicode's tables name, beyond those above.
const (
	// Default-ignorable code points no other rule names, such as U+034F
	// and the Hangul fillers.
	RuleDefaultIgnorable = "hidden-default-ignorable"
	// Format characters no other rule names, such as the interlinear
	// annotation characters, which can hide the text between them.
	RuleFormatCharacter = "hidden-format-character"
	// The line and paragraph separators, U+2028 and U+2029.
	RuleLineSeparator = "hidden-line-separator"
	RulePrivateUse    = "hidden-private-use"
	RuleUnassigned    = "hidden-unassigned"
)
