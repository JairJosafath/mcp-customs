package store

import (
	"context"
	"errors"
	"strings"
	"testing"
)

var passHash = strings.Repeat("5f", 32)

func passOf(checkID, version string, conditional bool) Pass {
	return Pass{
		Hash:        Verdict{Hash: passHash, CheckID: checkID, ToolListHash: "t1", InstallSpec: "{}"},
		Approved:    &Approved{Kind: "npm", Name: "weather-mcp", Version: version, CheckID: checkID, ToolListHash: "t1"},
		Conditional: conditional,
		Verdict:     "pass",
	}
}

func TestStorePassesACheckInOneWrite(t *testing.T) {
	fake := newFakeDynamo()
	s := New(fake, "customs")
	if err := s.PutCheck(t.Context(), Check{ID: "c1", Status: StatusRunning}); err != nil {
		t.Fatal(err)
	}
	if err := s.PassCheck(t.Context(), passOf("c1", "1.0.0", false)); err != nil {
		t.Fatal(err)
	}
	check, _, _ := s.GetCheck(t.Context(), "c1")
	v, found, _ := s.GetVerdict(t.Context(), passHash)
	approved, _ := s.ListApproved(t.Context())
	if check.Status != StatusDone || check.Verdict != "pass" || !found || v.CheckID != "c1" ||
		len(approved) != 1 || approved[0].CheckID != "c1" || approved[0].Polled != "1.0.0" {
		t.Errorf("check %+v, HASH# %+v (%v), APPROVED %+v; want all three written", check, v, found, approved)
	}
}

func TestStoreWritesNoApprovalOfACheckItCantMarkDone(t *testing.T) {
	for name, cause := range map[string]func(*fakeDynamo){
		"no such check": func(*fakeDynamo) {},
		"an outage":     func(f *fakeDynamo) { f.err = errors.New("throttled") },
	} {
		t.Run(name, func(t *testing.T) {
			fake := newFakeDynamo()
			cause(fake)
			err := New(fake, "customs").PassCheck(t.Context(), passOf("c1", "1.0.0", false))
			if err == nil || len(fake.items) != 0 {
				t.Errorf("PassCheck = %v, items %v; want an error and nothing written", err, fake.items)
			}
			if name == "no such check" && !errors.Is(err, ErrNoCheck) {
				t.Errorf("PassCheck = %v, want %v", err, ErrNoCheck)
			}
		})
	}
}

func TestStorePassesARecheckOvertakenByANewerPollButLeavesItsApproval(t *testing.T) {
	fake := newFakeDynamo()
	s := New(fake, "customs")
	if err := approve(t.Context(), s, Approved{Kind: "npm", Name: "weather-mcp", Version: "1.0.2", CheckID: "c0"}, false); err != nil {
		t.Fatal(err)
	}
	if err := s.PutCheck(t.Context(), Check{ID: "c1", Status: StatusRunning}); err != nil {
		t.Fatal(err)
	}
	if err := s.PassCheck(t.Context(), passOf("c1", "1.0.1", true)); err != nil {
		t.Fatal(err)
	}
	check, _, _ := s.GetCheck(t.Context(), "c1")
	approved, _ := s.ListApproved(t.Context())
	if check.Status != StatusDone || len(approved) != 1 || approved[0].CheckID != "c0" {
		t.Errorf("check %+v, APPROVED %+v; want c1 done and c0's newer approval left", check, approved)
	}
}

func TestStoreRefusesAPassItCantKey(t *testing.T) {
	for name, p := range map[string]Pass{
		"bad hash":    {Hash: Verdict{Hash: "x", CheckID: "c1"}, Verdict: "pass"},
		"bad check":   {Hash: Verdict{Hash: passHash, CheckID: "c 1"}, Verdict: "pass"},
		"bad package": {Hash: Verdict{Hash: passHash, CheckID: "c1"}, Approved: &Approved{Kind: "npm"}, Verdict: "pass"},
	} {
		fake := newFakeDynamo()
		if err := New(fake, "customs").PassCheck(t.Context(), p); err == nil || len(fake.tables) != 0 {
			t.Errorf("%s: PassCheck = %v, %d calls; want refused without calling DynamoDB", name, err, len(fake.tables))
		}
	}
}

// approve approves a as a passing check does, with PassCheck: it creates
// the check that approves it (c0 when a names none) and passes it.
func approve(ctx context.Context, s *Store, a Approved, conditional bool) error {
	id := a.CheckID
	if id == "" {
		id = "c0"
	}
	if err := s.PutCheck(ctx, Check{ID: id, Status: StatusRunning}); err != nil && !errors.Is(err, ErrCheckExists) {
		return err
	}
	return s.PassCheck(ctx, Pass{Hash: Verdict{Hash: passHash, CheckID: id}, Approved: &a, Conditional: conditional, Verdict: "pass"})
}
