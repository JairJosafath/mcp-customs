package findings

import (
	"fmt"
	"slices"
	"strings"
	"unicode/utf8"
)

// A Scan is what ScanText found in one piece of server text.
type Scan struct {
	// Findings are the hidden characters and injection patterns found.
	Findings []Finding
	// Escaped is the text with each hidden character shown as a Go escape,
	// such as \u200B, safe to show a person.
	Escaped string
}

// ScanText scans one piece of server text (a description, a schema field, a
// result, a resource or a prompt) for hidden characters and injection
// patterns. Patterns are matched with the hidden characters removed and
// every blank (a Unicode space, a line break or a lookalike such as U+2800)
// read as a space, with any mark on it left out, so neither a zero-width
// space, an odd space nor an accent on one can split them.
func ScanText(text string) Scan {
	var escaped, visible strings.Builder
	seen := map[string][]string{}
	var order []string
	prev := rune(-1)
	// onBlank holds while the last character seen was a blank, or a mark
	// on one: a mark on a blank is left out of what the patterns see, so
	// an accent can't split their words.
	onBlank := false
	for i, r := range text {
		next := rune(-1)
		// An invalid byte is one byte wide, though range answers U+FFFD.
		if _, width := utf8.DecodeRuneInString(text[i:]); i+width < len(text) {
			next, _ = utf8.DecodeRuneInString(text[i+width:])
		}
		rule, hidden := hiddenRule(prev, r, next)
		prev = r
		switch {
		case blank(r):
			visible.WriteRune(' ')
			onBlank = true
		case onBlank && mark(r):
		case !hidden:
			visible.WriteRune(r)
			onBlank = false
		}
		if !hidden {
			escaped.WriteRune(r)
			continue
		}
		e := escapeRune(r)
		escaped.WriteString(e)
		if _, ok := seen[rule]; !ok {
			order = append(order, rule)
		}
		if !slices.Contains(seen[rule], e) {
			seen[rule] = append(seen[rule], e)
		}
	}
	found := make([]Finding, 0, len(order))
	for _, rule := range order {
		found = append(found, Finding{Source: Code, Rule: rule, Evidence: strings.Join(seen[rule], " ")})
	}
	found = append(found, scanInjection(visible.String())...)
	return Scan{Findings: found, Escaped: escaped.String()}
}

func escapeRune(r rune) string {
	if r <= 0xFFFF {
		return fmt.Sprintf(`\u%04X`, r)
	}
	return fmt.Sprintf(`\U%08X`, r)
}
