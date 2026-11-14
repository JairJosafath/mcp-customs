package findings

import "regexp"

type pattern struct {
	rule string
	re   *regexp.Regexp
}

// injectionPatterns are the known shapes of text that steers a model:
// instructions to it, paths to secrets, and requests to send secrets back.
var injectionPatterns = []pattern{
	{RuleInstruction, regexp.MustCompile(`(?i)\b(ignore|disregard|forget)\s+(all\s+|any\s+)?(the\s+|your\s+)?(previous|prior|above|earlier|preceding)\b`)},
	{RuleInstruction, regexp.MustCompile(`(?i)\b(do\s+not|don'?t|never)\s+(tell|inform|notify|alert|(mention|reveal|show)\s+(this\s+|it\s+)?to)\s+the\s+user\b`)},
	{RuleInstruction, regexp.MustCompile(`(?i)\bbefore\s+(using|calling|invoking|running)\s+(this|the|any)\s+tools?\b`)},
	{RuleSensitivePath, regexp.MustCompile(`~/\.ssh\b`)},
	{RuleSensitivePath, regexp.MustCompile(`(?i)\bid_(rsa|ed25519|ecdsa|dsa)\b`)},
	{RuleSensitivePath, regexp.MustCompile(`(?:^|[^\w.])\.env\b`)},
	{RuleSensitivePath, regexp.MustCompile(`(?i)\.aws/credentials\b`)},
	{RuleSecretResend, regexp.MustCompile(`(?i)\bagain\s+with\s+(the\s+)?(contents?|value|text)\s+of\b`)},
	{RuleSecretResend, regexp.MustCompile(`(?i)\b(include|pass|send|provide|paste|attach|put)\s+(your|the\s+user'?s|the)\s+(\w+\s+){0,2}(api[\s_-]?keys?|tokens?|secrets?|passwords?|credentials|private\s+keys?|ssh\s+keys?)\b`)},
}

func scanInjection(text string) []Finding {
	var found []Finding
	for _, p := range injectionPatterns {
		if m := p.re.FindString(text); m != "" {
			found = append(found, Finding{Source: Code, Rule: p.rule, Evidence: m})
		}
	}
	return found
}
