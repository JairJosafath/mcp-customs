package findings

import (
	"slices"
	"unicode"
)

type runeRange struct{ lo, hi rune }

type hiddenClass struct {
	rule   string
	ranges []runeRange
}

// hiddenClasses are the characters a person can't see but a model reads,
// that have a rule of their own. The ANSI escapes come before the other
// controls, which leave out \t and \n.
var hiddenClasses = []hiddenClass{
	{RuleANSIEscape, []runeRange{{0x1B, 0x1B}, {0x9B, 0x9B}}},
	{RuleControlCharacter, []runeRange{{0x00, 0x08}, {0x0B, 0x1F}, {0x7F, 0x9F}}},
	{RuleTagCharacters, []runeRange{{0xE0000, 0xE007F}}},
	{RuleZeroWidth, []runeRange{{0x00AD, 0x00AD}, {0x180E, 0x180E}, {0x200B, 0x200D}, {0x2060, 0x2064}, {0xFEFF, 0xFEFF}}},
	{RuleBidiControl, []runeRange{{0x061C, 0x061C}, {0x200E, 0x200F}, {0x202A, 0x202E}, {0x2066, 0x2069}}},
}

// hiddenTables are the rest, by Unicode's own tables: the default-ignorable
// code points (variation selectors and the rest), the format characters,
// the line and paragraph separators, private use, and every code point
// not assigned. Go's tables are Unicode 15.0's, so a code point assigned
// since is unassigned in them: assignedSinceGo, generated from a newer
// Unicode, holds the visible ones, which are no finding. The first table
// a character is in names its rule.
var hiddenTables = []struct {
	rule  string
	table *unicode.RangeTable
}{
	{RuleVariationSelector, unicode.Variation_Selector},
	{RuleDefaultIgnorable, unicode.Other_Default_Ignorable_Code_Point},
	{RuleFormatCharacter, unicode.Cf},
	{RuleLineSeparator, unicode.Zl},
	{RuleLineSeparator, unicode.Zp},
	{RulePrivateUse, unicode.Co},
	{RuleUnassigned, unicode.Cn},
}

// U+FE0E and U+FE0F pick text or emoji style. Each is no finding right
// after a character Unicode gives that variation sequence; anywhere else,
// after a letter or another selector, it carries no meaning and can carry
// bits past a reader. The other variation selectors are always a finding.
const (
	textStyle  = 0xFE0E
	emojiStyle = 0xFE0F
)

// hiddenRule names the rule of r, the character after prev (-1 at the
// start), and whether r is hidden at all. A \r is hidden unless a \n
// follows it (beforeLF).
func hiddenRule(prev, r rune, beforeLF bool) (string, bool) {
	if r == '\r' && beforeLF {
		return "", false
	}
	for _, c := range hiddenClasses {
		if inRanges(c.ranges, r) {
			return c.rule, true
		}
	}
	if r == textStyle || r == emojiStyle {
		if inRanges(emojiVariationBases, prev) {
			return "", false
		}
		return RuleVariationSelector, true
	}
	if inRanges(assignedSinceGo, r) {
		return "", false
	}
	for _, t := range hiddenTables {
		if unicode.Is(t.table, r) {
			return t.rule, true
		}
	}
	return "", false
}

// blankLookalikes look like a space but aren't in Unicode's White_Space:
// the braille blank and the Hangul fillers.
var blankLookalikes = []runeRange{{0x115F, 0x1160}, {0x2800, 0x2800}, {0x3164, 0x3164}, {0xFFA0, 0xFFA0}}

// blank reports whether r shows as a space, or as nothing between words:
// every Unicode space and line break, and the blank lookalikes. The
// injection patterns see each as one space.
func blank(r rune) bool {
	return unicode.IsSpace(r) || unicode.Is(unicode.Zs, r) || inRanges(blankLookalikes, r)
}

// inRanges reports whether r is in rs, which are sorted and don't overlap.
func inRanges(rs []runeRange, r rune) bool {
	_, found := slices.BinarySearchFunc(rs, r, func(rr runeRange, r rune) int {
		switch {
		case r < rr.lo:
			return 1
		case r > rr.hi:
			return -1
		}
		return 0
	})
	return found
}
