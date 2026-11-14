// Package canary makes the fake secrets planted in the sandbox for one run:
// fresh values in the real formats, with valid checksums, so a server can't
// tell them from a developer's own.
package canary

// Kind names what a canary pretends to be.
type Kind string

// The kinds of canary each run plants.
const (
	GitHubToken    Kind = "github-token"
	AWSAccessKeyID Kind = "aws-access-key-id"
	AWSSecretKey   Kind = "aws-secret-access-key" //nolint:gosec // a kind's name, not a credential
	SSHPrivateKey  Kind = "ssh-private-key"
	Email          Kind = "email"
	Password       Kind = "password"
)

// A Canary is one planted value.
type Canary struct {
	Kind  Kind   `json:"kind"`
	Value string `json:"value"`
}

// A Set is the canaries of one run, one of each kind.
type Set []Canary

// New makes a fresh set from crypto/rand: no value is shared with another run.
func New() Set {
	return Set{
		{GitHubToken, githubToken()},
		{AWSAccessKeyID, awsAccessKeyID()},
		{AWSSecretKey, awsSecretKey()},
		{SSHPrivateKey, sshPrivateKey()},
		{Email, email()},
		{Password, password()},
	}
}

// Get returns the value of the canary of a kind, or "" when the set has none.
func (s Set) Get(k Kind) string {
	for _, c := range s {
		if c.Kind == k {
			return c.Value
		}
	}
	return ""
}
