package harness

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// CanaryKind names what a canary pretends to be, as internal/canary names it.
type CanaryKind string

// The kinds of canary the fake developer setup holds.
const (
	CanaryGitHubToken    CanaryKind = "github-token"
	CanaryAWSAccessKeyID CanaryKind = "aws-access-key-id"
	CanaryAWSSecretKey   CanaryKind = "aws-secret-access-key" //nolint:gosec // a kind's name, not a credential
	CanarySSHPrivateKey  CanaryKind = "ssh-private-key"
	CanaryEmail          CanaryKind = "email"
	CanaryPassword       CanaryKind = "password"
)

// A Canary is one planted value of the run.
type Canary struct {
	Kind  CanaryKind `json:"kind"`
	Value string     `json:"value"`
}

// canaryKinds are the kinds the home needs, each exactly once.
var canaryKinds = []CanaryKind{
	CanaryGitHubToken, CanaryAWSAccessKeyID, CanaryAWSSecretKey,
	CanarySSHPrivateKey, CanaryEmail, CanaryPassword,
}

// canarySet checks a run's canaries, one of each kind, and indexes them.
func canarySet(list []Canary) (map[CanaryKind]string, error) {
	set := map[CanaryKind]string{}
	for _, c := range list {
		if !knownCanary(c.Kind) {
			return nil, fmt.Errorf("unknown canary kind %q", c.Kind)
		}
		if _, dup := set[c.Kind]; dup {
			return nil, fmt.Errorf("two canaries of kind %q", c.Kind)
		}
		if strings.TrimSpace(c.Value) == "" {
			return nil, fmt.Errorf("the canary of kind %q is empty", c.Kind)
		}
		if c.Kind != CanarySSHPrivateKey && strings.ContainsAny(c.Value, "\r\n") {
			return nil, fmt.Errorf("the canary of kind %q spans lines", c.Kind)
		}
		set[c.Kind] = c.Value
	}
	for _, k := range canaryKinds {
		if _, ok := set[k]; !ok {
			return nil, fmt.Errorf("no canary of kind %q", k)
		}
	}
	return set, nil
}

func knownCanary(k CanaryKind) bool {
	for _, known := range canaryKinds {
		if k == known {
			return true
		}
	}
	return false
}

// homeFile is one file of the fake developer setup.
type homeFile struct {
	path string
	mode os.FileMode
	body string
}

// homeFiles is a developer's setup, holding the run's canaries where a
// developer's own secrets would be.
func homeFiles(c map[CanaryKind]string) []homeFile {
	key := strings.TrimRight(c[CanarySSHPrivateKey], "\n") + "\n"
	return []homeFile{
		{".ssh/id_ed25519", 0o600, key},
		{".aws/credentials", 0o600, "[default]\naws_access_key_id = " + c[CanaryAWSAccessKeyID] +
			"\naws_secret_access_key = " + c[CanaryAWSSecretKey] + "\n"},
		{".aws/config", 0o644, "[default]\nregion = us-east-1\noutput = json\n"},
		{".npmrc", 0o600, "@acme:registry=https://npm.pkg.github.com\n" +
			"//npm.pkg.github.com/:_authToken=" + c[CanaryGitHubToken] + "\n"},
		{".gitconfig", 0o644, "[user]\n\tname = Alex Morgan\n\temail = " + c[CanaryEmail] +
			"\n[credential]\n\thelper = store\n[init]\n\tdefaultBranch = main\n"},
		// Go's own usage counters would otherwise show as files the install wrote.
		{".config/go/telemetry/mode", 0o644, "off 2026-01-05\n"},
		{".git-credentials", 0o600, "https://alexmorgan:" + c[CanaryGitHubToken] + "@github.com\n"},
		{".bash_history", 0o600, strings.Join([]string{
			"cd ~/projects/api",
			"git pull",
			"export GITHUB_TOKEN=" + c[CanaryGitHubToken],
			"aws s3 ls",
			"ssh-add ~/.ssh/id_ed25519",
			"mysql -u admin -p'" + c[CanaryPassword] + "' -h db.internal",
			"npm test",
		}, "\n") + "\n"},
	}
}

// plantHome writes the fake developer setup into the account's home, owned
// by the account. It runs before any code of the server does.
func plantHome(a Account, canaries map[CanaryKind]string) error {
	for _, f := range homeFiles(canaries) {
		path := filepath.Join(a.Home, f.path)
		if err := mkdirOwned(a, filepath.Dir(path)); err != nil {
			return err
		}
		if err := os.WriteFile(path, []byte(f.body), f.mode); err != nil {
			return fmt.Errorf("plant %s: %w", f.path, err)
		}
		if err := os.Chmod(path, f.mode); err != nil {
			return fmt.Errorf("plant %s: %w", f.path, err)
		}
		if err := chown(a, path); err != nil {
			return err
		}
	}
	return nil
}

// mkdirOwned makes dir and its missing parents under the account's home,
// owned by the account, private to it.
func mkdirOwned(a Account, dir string) error {
	rel, err := filepath.Rel(a.Home, dir)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return fmt.Errorf("%s is outside the home %s", dir, a.Home)
	}
	path := a.Home
	for _, part := range append([]string{"."}, strings.Split(rel, string(filepath.Separator))...) {
		path = filepath.Join(path, part)
		if err := os.Mkdir(path, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
			return fmt.Errorf("make %s: %w", path, err)
		}
		if err := chown(a, path); err != nil {
			return err
		}
	}
	return nil
}

func chown(a Account, path string) error {
	if !a.Switch {
		return nil
	}
	if err := os.Lchown(path, int(a.UID), int(a.GID)); err != nil {
		return fmt.Errorf("give %s to %s: %w", path, a.Name, err)
	}
	return nil
}
