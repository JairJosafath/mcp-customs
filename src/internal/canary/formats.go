package canary

import (
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"hash/crc32"
)

// githubToken makes a classic personal access token: ghp_, 30 random
// base62 characters and their CRC32, base62-encoded in six characters.
func githubToken() string {
	body := randomString(base62, 30)
	return "ghp_" + body + githubChecksum(body)
}

func githubChecksum(body string) string {
	n := crc32.ChecksumIEEE([]byte(body))
	out := make([]byte, 6)
	for i := len(out) - 1; i >= 0; i-- {
		out[i] = base62[n%62]
		n /= 62
	}
	return string(out)
}

// awsAccessKeyID makes a long-term access key ID: AKIA and 16 base32
// characters carrying a twelve-digit account ID, as real keys do.
func awsAccessKeyID() string {
	account := uint64(100_000_000_000 + randomIndex(900_000)*1_000_000 + randomIndex(1_000_000)) //nolint:gosec // both indexes are non-negative
	b := randomBytes(10)
	head := 1<<47 | account<<7 | uint64(b[0]&0x7f)
	var six [8]byte
	binary.BigEndian.PutUint64(six[:], head)
	copy(b, six[2:])
	return "AKIA" + base32.StdEncoding.EncodeToString(b)
}

// accountOf is the account ID an access key ID carries.
func accountOf(keyID string) (uint64, error) {
	b, err := base32.StdEncoding.DecodeString(keyID[4:])
	if err != nil {
		return 0, fmt.Errorf("decode access key ID: %w", err)
	}
	var six [8]byte
	copy(six[2:], b[:6])
	return binary.BigEndian.Uint64(six[:]) & 0x7fffffffff80 >> 7, nil
}

// awsSecretKey makes a 40-character secret access key.
func awsSecretKey() string {
	return base64.StdEncoding.EncodeToString(randomBytes(30))
}

var (
	firstNames = []string{"alex", "sam", "jordan", "maria", "li", "noah", "emma", "omar", "sofia", "lucas", "ana", "ravi"}
	lastNames  = []string{"morgan", "chen", "garcia", "smith", "kowalski", "silva", "patel", "novak", "jansen", "kim", "ito", "reyes"}
	mailHosts  = []string{"gmail.com", "outlook.com", "proton.me", "fastmail.com"}
)

// email makes a personal address with a six-digit number.
func email() string {
	return fmt.Sprintf("%s.%s%s@%s", randomChoice(firstNames), randomChoice(lastNames), randomString(digits, 6), randomChoice(mailHosts))
}

// password makes a 20-character password with every kind of character.
func password() string {
	b := []byte{
		upper[randomIndex(len(upper))],
		lower[randomIndex(len(lower))],
		digits[randomIndex(len(digits))],
		symbols[randomIndex(len(symbols))],
	}
	b = append(b, randomString(alphaNum+symbols, 16)...)
	for i := len(b) - 1; i > 0; i-- {
		j := randomIndex(i + 1)
		b[i], b[j] = b[j], b[i]
	}
	return string(b)
}
