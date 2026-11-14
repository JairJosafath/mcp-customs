package web

import "testing"

func TestVisibleEscapesEveryCharacterAPersonCannotSee(t *testing.T) {
	for name, r := range map[string]rune{
		"a bell":                               0x07,
		"a backspace":                          0x08,
		"a carriage return":                    0x0D,
		"a delete":                             0x7F,
		"a C1 control":                         0x85,
		"a soft hyphen":                        0xAD,
		"a combining grapheme joiner":          0x034F,
		"an Arabic letter mark":                0x061C,
		"a Khmer inherent vowel":               0x17B4,
		"a Mongolian free variation selector":  0x180B,
		"the third Mongolian selector":         0x180D,
		"a Mongolian vowel separator":          0x180E,
		"a zero-width space":                   0x200B,
		"a left-to-right mark":                 0x200E,
		"a line separator":                     0x2028,
		"a paragraph separator":                0x2029,
		"a right-to-left override":             0x202E,
		"a word joiner":                        0x2060,
		"an unassigned code point":             0x2065,
		"an inhibit symmetric swapping":        0x206A,
		"a Hangul filler":                      0x3164,
		"a private-use code point":             0xE000,
		"a variation selector":                 0xFE00,
		"a byte-order mark":                    0xFEFF,
		"an interlinear annotation anchor":     0xFFF9,
		"an interlinear annotation separator":  0xFFFA,
		"an interlinear annotation terminator": 0xFFFB,
		"a replacement character":              0xFFFD,
		"a Kaithi number sign":                 0x110BD,
		"an Egyptian hieroglyph joiner":        0x13430,
		"a musical symbol begin beam":          0x1D173,
		"a musical symbol end phrase":          0x1D17A,
		"a tag character":                      0xE0041,
		"a supplementary variation selector":   0xE0100,
		"a supplementary private-use":          0xF0000,
	} {
		in := "a" + string(r) + "b"
		want := "a" + escapeRune(r) + "b"
		if got := visible(in); got != want {
			t.Errorf("%s (U+%04X): visible = %q, want %q", name, r, got, want)
		}
	}
}

func TestVisibleKeepsWhatAPersonCanSee(t *testing.T) {
	for _, text := range []string{
		"plain ASCII, with punctuation: <>&\"'",
		"a tab\tand a new line\n",
		"accents: é, ü, ñ; scripts: 日本語, العربية, עברית, Ελληνικά",
		"an emoji with its presentation selector: ❤️, text style: ❤︎",
		"a no-break space: a b",
	} {
		if got := visible(text); got != text {
			t.Errorf("visible(%q) = %q, want it unchanged", text, got)
		}
	}
}
