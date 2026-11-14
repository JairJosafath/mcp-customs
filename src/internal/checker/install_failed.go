package checker

import (
	"strings"

	"github.com/JairJosafath/mcp-customs/src/internal/findings"
)

// maxInstallEvidence bounds the harness's message an install-failed
// finding keeps.
const maxInstallEvidence = 512

// installFailed is the code finding of an install the harness could not
// do, with the harness's message, which names what failed, as evidence.
func installFailed(message string) findings.Finding {
	if len(message) > maxInstallEvidence {
		message = strings.ToValidUTF8(message[:maxInstallEvidence], "")
	}
	return findings.Finding{Source: findings.Code, Rule: findings.RuleInstallFailed, Evidence: message}
}

// remoteUnsupported is the code finding of a remote server, which the
// sandbox doesn't connect to yet, so nothing of it is checked.
func remoteUnsupported(ref string) findings.Finding {
	return findings.Finding{
		Source:   findings.Code,
		Rule:     findings.RuleRemoteUnsupported,
		Evidence: "Remote servers aren't checked yet: no sandbox connected to " + ref + ".",
	}
}
