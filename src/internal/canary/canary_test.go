package canary

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"regexp"
	"strings"
	"testing"
)

func TestNewMakesEachKindInItsRealFormat(t *testing.T) {
	tests := []struct {
		kind   Kind
		format *regexp.Regexp
	}{
		{GitHubToken, regexp.MustCompile(`^ghp_[0-9A-Za-z]{36}$`)},
		{AWSAccessKeyID, regexp.MustCompile(`^AKIA[A-Z2-7]{16}$`)},
		{AWSSecretKey, regexp.MustCompile(`^[A-Za-z0-9/+]{40}$`)},
		{SSHPrivateKey, regexp.MustCompile(`^-----BEGIN OPENSSH PRIVATE KEY-----\n([A-Za-z0-9/+]{70}\n)+[A-Za-z0-9/+=]{1,70}\n-----END OPENSSH PRIVATE KEY-----\n$`)},
		{Email, regexp.MustCompile(`^[a-z]+\.[a-z]+\d{6}@[a-z]+\.[a-z]+$`)},
		{Password, regexp.MustCompile(`^[0-9A-Za-z!#$%&*+\-=?@^_]{20}$`)},
	}
	set := New()
	if len(set) != len(tests) {
		t.Fatalf("New made %d canaries, want %d", len(set), len(tests))
	}
	for _, tt := range tests {
		t.Run(string(tt.kind), func(t *testing.T) {
			if v := set.Get(tt.kind); !tt.format.MatchString(v) {
				t.Errorf("%s = %q, not in its format", tt.kind, v)
			}
		})
	}
}

func TestGitHubTokenHasValidChecksum(t *testing.T) {
	token := New().Get(GitHubToken)
	body, sum := token[4:34], token[34:]
	if got := githubChecksum(body); got != sum {
		t.Errorf("checksum of %q = %q, token carries %q", body, got, sum)
	}
}

func TestGitHubChecksumMatchesKnownToken(t *testing.T) {
	// CRC32 (IEEE) of the body is 0x806D9A54 = 2154666580, which is "2LolCm"
	// in base62 with the alphabet 0-9A-Za-z.
	const body = "abcdefghijklmnopqrstuvwxyz0123"
	if got := githubChecksum(body); got != "2LolCm" {
		t.Errorf("githubChecksum(%q) = %q, want %q", body, got, "2LolCm")
	}
}

func TestAWSAccessKeyIDCarriesTwelveDigitAccount(t *testing.T) {
	account, err := accountOf(New().Get(AWSAccessKeyID))
	if err != nil {
		t.Fatal(err)
	}
	if account < 100_000_000_000 || account > 999_999_999_999 {
		t.Errorf("account = %d, want twelve digits", account)
	}
}

func TestAWSAccountOfKnownKey(t *testing.T) {
	// The example from Truffle Security's research into account IDs in keys.
	account, err := accountOf("ASIAY34FZKBOKMUTVV7A")
	if err != nil {
		t.Fatal(err)
	}
	if account != 609629065308 {
		t.Errorf("account = %d, want 609629065308", account)
	}
}

func TestSSHPrivateKeyIsAnOpenSSHEd25519Key(t *testing.T) {
	pem := New().Get(SSHPrivateKey)
	lines := strings.Split(strings.TrimSpace(pem), "\n")
	body, err := base64.StdEncoding.DecodeString(strings.Join(lines[1:len(lines)-1], ""))
	if err != nil {
		t.Fatalf("decode body: %v", err)
	}
	rest, ok := bytes.CutPrefix(body, []byte(sshMagic))
	if !ok {
		t.Fatal("body does not start with openssh-key-v1")
	}
	for _, want := range []string{"none", "none", ""} {
		var got []byte
		got, rest = readSSHString(t, rest)
		if string(got) != want {
			t.Fatalf("header field = %q, want %q", got, want)
		}
	}
	rest = rest[4:]
	pubBlob, rest := readSSHString(t, rest)
	section, _ := readSSHString(t, rest)
	if !bytes.Equal(section[0:4], section[4:8]) {
		t.Error("check integers differ")
	}
	if len(section)%8 != 0 {
		t.Errorf("private section is %d bytes, want a multiple of 8", len(section))
	}
	keyType, pubRest := readSSHString(t, pubBlob)
	pub, _ := readSSHString(t, pubRest)
	if string(keyType) != sshKeyType {
		t.Errorf("key type = %q, want %q", keyType, sshKeyType)
	}
	secRest := section[8+len(pubBlob):]
	priv, _ := readSSHString(t, secRest)
	if derived := ed25519.PrivateKey(priv).Public(); !ed25519.PublicKey(pub).Equal(derived) {
		t.Error("public key does not match the private key")
	}
}

func readSSHString(t *testing.T, b []byte) (value, rest []byte) {
	t.Helper()
	if len(b) < 4 {
		t.Fatalf("%d bytes left, want a length", len(b))
	}
	n := binary.BigEndian.Uint32(b)
	if int64(n) > int64(len(b)-4) {
		t.Fatalf("string of %d bytes in %d", n, len(b)-4)
	}
	return b[4 : 4+n], b[4+n:]
}

func TestTwoRunsShareNoValue(t *testing.T) {
	a, b := New(), New()
	for _, ca := range a {
		for _, cb := range b {
			if ca.Value == cb.Value {
				t.Errorf("%s and %s share %q", ca.Kind, cb.Kind, ca.Value)
			}
		}
	}
}

func TestPasswordHasEveryKindOfCharacter(t *testing.T) {
	p := password()
	for _, class := range []string{upper, lower, digits, symbols} {
		if !strings.ContainsAny(p, class) {
			t.Errorf("password %q has none of %q", p, class)
		}
	}
}

func TestGetUnknownKindIsEmpty(t *testing.T) {
	if got := New().Get("unknown"); got != "" {
		t.Errorf("Get(unknown) = %q, want empty", got)
	}
}
