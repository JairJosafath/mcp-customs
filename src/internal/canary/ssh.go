package canary

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"strings"
)

const (
	sshMagic   = "openssh-key-v1\x00"
	sshKeyType = "ssh-ed25519"
	sshComment = "dev@laptop"
	sshWidth   = 70
)

// sshPrivateKey makes an unencrypted ed25519 key in OpenSSH's format, as
// ssh-keygen writes it.
func sshPrivateKey() string {
	priv := ed25519.NewKeyFromSeed(randomBytes(ed25519.SeedSize))
	pub := priv[ed25519.SeedSize:]
	pubBlob := append(sshString([]byte(sshKeyType)), sshString(pub)...)

	check := randomBytes(4)
	section := append(append([]byte{}, check...), check...)
	section = append(section, pubBlob...)
	section = append(section, sshString(priv)...)
	section = append(section, sshString([]byte(sshComment))...)
	for i := byte(1); len(section)%8 != 0; i++ {
		section = append(section, i)
	}

	body := []byte(sshMagic)
	body = append(body, sshString([]byte("none"))...)
	body = append(body, sshString([]byte("none"))...)
	body = append(body, sshString(nil)...)
	body = binary.BigEndian.AppendUint32(body, 1)
	body = append(body, sshString(pubBlob)...)
	body = append(body, sshString(section)...)
	return pemBlock(base64.StdEncoding.EncodeToString(body))
}

func sshString(b []byte) []byte {
	out := binary.BigEndian.AppendUint32(nil, uint32(len(b))) //nolint:gosec // keys are far below 4 GiB
	return append(out, b...)
}

func pemBlock(encoded string) string {
	var sb strings.Builder
	sb.WriteString("-----BEGIN OPENSSH PRIVATE KEY-----\n")
	for len(encoded) > sshWidth {
		sb.WriteString(encoded[:sshWidth] + "\n")
		encoded = encoded[sshWidth:]
	}
	sb.WriteString(encoded + "\n-----END OPENSSH PRIVATE KEY-----\n")
	return sb.String()
}
