package canary

import "crypto/rand"

const (
	digits   = "0123456789"
	upper    = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	lower    = "abcdefghijklmnopqrstuvwxyz"
	symbols  = "!#$%&*+-=?@^_"
	base62   = digits + upper + lower
	alphaNum = base62
)

// randomBytes returns n bytes from crypto/rand, which never fails.
func randomBytes(n int) []byte {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return b
}

// randomIndex returns a uniform index in [0, n), for 0 < n < 2^32, by
// rejecting the values that would bias the remainder.
func randomIndex(n int) int {
	limit := (1 << 32) / n * n
	for {
		b := randomBytes(4)
		v := int(b[0])<<24 | int(b[1])<<16 | int(b[2])<<8 | int(b[3])
		if v < limit {
			return v % n
		}
	}
}

func randomString(alphabet string, n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = alphabet[randomIndex(len(alphabet))]
	}
	return string(b)
}

func randomChoice(options []string) string {
	return options[randomIndex(len(options))]
}
