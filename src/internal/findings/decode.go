package findings

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
)

// minRun is the shortest encoded run worth decoding: every canary is
// longer than this once encoded.
const minRun = 8

func isStdBase64(c byte) bool { return isAlphaNum(c) || c == '+' || c == '/' }

func isURLBase64(c byte) bool { return isAlphaNum(c) || c == '-' || c == '_' }

func isAlphaNum(c byte) bool {
	return c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9'
}

func isHex(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}

// lineBreaks are what wraps an encoded payload: raw line breaks, as
// coreutils base64, MIME and PEM write them, and the same escaped in JSON.
var lineBreaks = [][]byte{[]byte("\r"), []byte("\n"), []byte(`\r`), []byte(`\n`)}

// unwrap removes every line break, so a wrapped payload decodes as one run.
// Text glued on in front of a run is harmless: decoding at each alignment
// finds the payload after it.
func unwrap(data []byte) []byte {
	for _, lb := range lineBreaks {
		data = bytes.ReplaceAll(data, lb, nil)
	}
	return data
}

// runs splits data into the maximal runs of bytes in an alphabet.
func runs(data []byte, in func(byte) bool) [][]byte {
	var out [][]byte
	start := -1
	for i, c := range data {
		switch {
		case in(c) && start < 0:
			start = i
		case !in(c) && start >= 0:
			out = append(out, data[start:i])
			start = -1
		}
	}
	if start >= 0 {
		out = append(out, data[start:])
	}
	return out
}

// decodeBase64Runs decodes each run of base64 in data at each of the four
// alignments, so a payload glued to a prefix still decodes.
func decodeBase64Runs(data []byte, enc *base64.Encoding, in func(byte) bool) [][]byte {
	var out [][]byte
	for _, run := range runs(data, in) {
		for skip := 0; skip < 4 && len(run)-skip >= minRun; skip++ {
			r := run[skip:]
			if len(r)%4 == 1 {
				r = r[:len(r)-1]
			}
			if d, err := enc.DecodeString(string(r)); err == nil {
				out = append(out, d)
			}
		}
	}
	return out
}

// decodeHexRuns decodes each run of hex digits in data at both alignments.
func decodeHexRuns(data []byte) [][]byte {
	var out [][]byte
	for _, run := range runs(data, isHex) {
		for skip := 0; skip < 2 && len(run)-skip >= minRun; skip++ {
			r := run[skip:]
			r = r[:len(r)/2*2]
			if d, err := hex.DecodeString(string(r)); err == nil {
				out = append(out, d)
			}
		}
	}
	return out
}

// percentDecode undoes URL encoding leniently: each valid %XX becomes its
// byte, + becomes a space, and anything else is kept.
func percentDecode(data []byte) []byte {
	out := make([]byte, 0, len(data))
	for i := 0; i < len(data); i++ {
		switch {
		case data[i] == '+':
			out = append(out, ' ')
		case data[i] == '%' && i+2 < len(data) && isHex(data[i+1]) && isHex(data[i+2]):
			b, _ := hex.DecodeString(string(data[i+1 : i+3]))
			out = append(out, b...)
			i += 2
		default:
			out = append(out, data[i])
		}
	}
	return out
}
