package store

import (
	"errors"
	"strings"
	"testing"
)

func TestCheckPKAcceptsOnlyAnID(t *testing.T) {
	for name, tc := range map[string]struct {
		id   string
		want string
		err  error
	}{
		"an id":     {"c-1_A", "CHECK#c-1_A", nil},
		"empty":     {"", "", ErrBadCheckID},
		"a hash":    {"a#b", "", ErrBadCheckID},
		"too long":  {strings.Repeat("a", 65), "", ErrBadCheckID},
		"the limit": {strings.Repeat("a", 64), "CHECK#" + strings.Repeat("a", 64), nil},
	} {
		got, err := checkPK(tc.id)
		if got != tc.want || !errors.Is(err, tc.err) {
			t.Errorf("%s: checkPK(%q) = %q, %v; want %q, %v", name, tc.id, got, err, tc.want, tc.err)
		}
	}
}

func TestStepSKPadsTheNumberSoStepsSortInOrder(t *testing.T) {
	for name, tc := range map[string]struct {
		seq  int
		want string
		err  error
	}{
		"the first": {1, "STEP#0001", nil},
		"the last":  {MaxSeq, "STEP#9999", nil},
		"zero":      {0, "", ErrBadSeq},
		"too many":  {MaxSeq + 1, "", ErrBadSeq},
	} {
		got, err := stepSK(tc.seq)
		if got != tc.want || !errors.Is(err, tc.err) {
			t.Errorf("%s: stepSK(%d) = %q, %v; want %q, %v", name, tc.seq, got, err, tc.want, tc.err)
		}
	}
}

func TestHashPKAcceptsOnlyASHA256(t *testing.T) {
	hash := strings.Repeat("ab", 32)
	for name, tc := range map[string]struct {
		hash string
		want string
		err  error
	}{
		"a hash":      {hash, "HASH#" + hash, nil},
		"upper case":  {strings.ToUpper(hash), "", ErrBadHash},
		"too short":   {hash[:63], "", ErrBadHash},
		"not hex":     {strings.Repeat("zz", 32), "", ErrBadHash},
		"with a hash": {"#" + hash[1:], "", ErrBadHash},
	} {
		got, err := hashPK(tc.hash)
		if got != tc.want || !errors.Is(err, tc.err) {
			t.Errorf("%s: hashPK(%q) = %q, %v; want %q, %v", name, tc.hash, got, err, tc.want, tc.err)
		}
	}
}
