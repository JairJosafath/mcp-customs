// Package store reads and writes what the Checker and the web function
// share: the items of one DynamoDB table, as docs/contracts.md ("Store")
// lays them out.
package store

import (
	"errors"
	"fmt"
	"regexp"
)

// Status is where a check is.
type Status string

// The statuses of a check.
const (
	StatusRunning Status = "running"
	StatusDone    Status = "done"
	StatusFailed  Status = "failed"
)

// Submission is what was submitted for a check: an MCP server by its kind
// (go, npm, pypi or remote) and its reference (name@version or a URL).
type Submission struct {
	Kind string `json:"kind"`
	Ref  string `json:"ref"`
}

// Check is a check's META item.
type Check struct {
	ID           string
	Submission   Submission
	Status       Status
	Verdict      string
	ExecutionARN string
	CallbackID   string
}

// Finding is one reason for a verdict: who found it (code or model), the
// rule, and the evidence.
type Finding struct {
	Source   string `json:"source"`
	Rule     string `json:"rule"`
	Evidence string `json:"evidence"`
}

// Step is one STEP# item of a check: what ran, its findings and a one-line
// summary, the web page's timeline.
type Step struct {
	Seq      int
	Name     string
	Summary  string
	Findings []Finding
}

// Verdict is a HASH# item: the approved check of a dependency-set hash.
type Verdict struct {
	Hash         string
	CheckID      string
	ToolListHash string
	InstallSpec  string
}

// The sort keys of the items that have a fixed one.
const (
	metaSK    = "META"
	verdictSK = "VERDICT"
	// stepPrefix starts every step's sort key.
	stepPrefix = "STEP#"
	// MaxSeq is the largest step number: four digits keep the steps in order.
	MaxSeq = 9999
)

// The errors of a key that can't be stored.
var (
	ErrBadCheckID = errors.New(`a check id must be 1 to 64 letters, digits, "-" or "_"`)
	ErrBadSeq     = fmt.Errorf("a step's number must be 1 to %d", MaxSeq)
	ErrBadHash    = errors.New("a hash must be 64 lowercase hexadecimal digits")
)

var (
	checkIDPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
	hashPattern    = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// ValidCheckID reports whether id can name a check.
func ValidCheckID(id string) bool { return checkIDPattern.MatchString(id) }

// checkPK is the partition key of a check's items.
func checkPK(id string) (string, error) {
	if !ValidCheckID(id) {
		return "", ErrBadCheckID
	}
	return "CHECK#" + id, nil
}

// stepSK is the sort key of a check's step seq, zero-padded so the steps
// sort in order.
func stepSK(seq int) (string, error) {
	if seq < 1 || seq > MaxSeq {
		return "", ErrBadSeq
	}
	return fmt.Sprintf("%s%04d", stepPrefix, seq), nil
}

// hashPK is the partition key of a dependency-set hash's verdict.
func hashPK(hash string) (string, error) {
	if !hashPattern.MatchString(hash) {
		return "", ErrBadHash
	}
	return "HASH#" + hash, nil
}
