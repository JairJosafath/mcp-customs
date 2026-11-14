package findings

import (
	"fmt"
	"slices"
	"strings"
)

// A Scan is what ScanText found in one piece of server text.
type Scan struct {
	// Findings are the hidden characters and injection patterns found.
	Findings []Finding
	// Escaped is the text with each hidden character shown as a Go escape,
	// such as \u200B, safe to show a person.
	Escaped string
}

type runeRange struct{ lo, hi rune }

type hiddenClass struct {
	rule   string
	ranges []runeRange
}

// hiddenClasses are the characters a person can't see but a model reads.
var hiddenClasses = []hiddenClass{
	{RuleANSIEscape, []runeRange{{0x1B, 0x1B}, {0x9B, 0x9B}}},
	{RuleTagCharacters, []runeRange{{0xE0000, 0xE007F}}},
	{RuleZeroWidth, []runeRange{{0x00AD, 0x00AD}, {0x180E, 0x180E}, {0x200B, 0x200D}, {0x2060, 0x2064}, {0xFEFF, 0xFEFF}}},
	{RuleBidiControl, []runeRange{{0x061C, 0x061C}, {0x200E, 0x200F}, {0x202A, 0x202E}, {0x2066, 0x2069}}},
	// U+FE0E and U+FE0F, which pick text or emoji style, are left out: they
	// follow most emoji. The rest carry no meaning, and are used to smuggle
	// bytes past a reader.
	{RuleVariationSelector, []runeRange{{0xFE00, 0xFE0D}, {0xE0100, 0xE01EF}}},
}

// ScanText scans one piece of server text (a description, a schema field, a
// result, a resource or a prompt) for hidden characters and injection
// patterns. Patterns are matched with the hidden characters removed, so a
// zero-width space can't split them.
func ScanText(text string) Scan {
	var escaped, visible strings.Builder
	seen := map[string][]string{}
	var order []string
	for _, r := range text {
		rule, hidden := hiddenRule(r)
		if !hidden {
			escaped.WriteRune(r)
			visible.WriteRune(r)
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

func hiddenRule(r rune) (string, bool) {
	for _, c := range hiddenClasses {
		for _, rr := range c.ranges {
			if r >= rr.lo && r <= rr.hi {
				return c.rule, true
			}
		}
	}
	return "", false
}

func escapeRune(r rune) string {
	if r <= 0xFFFF {
		return fmt.Sprintf(`\u%04X`, r)
	}
	return fmt.Sprintf(`\U%08X`, r)
}
