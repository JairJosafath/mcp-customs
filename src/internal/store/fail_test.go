package store

import (
	"errors"
	"testing"
)

func TestStoreFailsACheckOnlyWhileItIsNotDone(t *testing.T) {
	for _, tt := range []struct {
		status Status
		want   error
		after  Status
	}{
		{StatusRunning, nil, StatusFailed},
		{StatusWaiting, nil, StatusFailed},
		{StatusFailed, nil, StatusFailed},
		{StatusDone, ErrCheckDone, StatusDone},
	} {
		s := New(newFakeDynamo(), "customs")
		if err := s.PutCheck(t.Context(), Check{ID: "c1", Status: tt.status}); err != nil {
			t.Fatal(err)
		}
		err := s.FailCheck(t.Context(), "c1")
		check, _, _ := s.GetCheck(t.Context(), "c1")
		if !errors.Is(err, tt.want) || (tt.want == nil && err != nil) || check.Status != tt.after {
			t.Errorf("%s: FailCheck = %v, status %s; want %v, %s", tt.status, err, check.Status, tt.want, tt.after)
		}
	}
}

func TestStoreFailsNoCheckThatDoesNotExist(t *testing.T) {
	fake := newFakeDynamo()
	if err := New(fake, "customs").FailCheck(t.Context(), "missing"); !errors.Is(err, ErrNoCheck) || len(fake.items) != 0 {
		t.Errorf("FailCheck = %v, items %v; want %v and nothing made", err, fake.items, ErrNoCheck)
	}
}

func TestStoreRefusesToFailABadCheckIDWithoutCallingDynamoDB(t *testing.T) {
	fake := newFakeDynamo()
	if err := New(fake, "customs").FailCheck(t.Context(), "c 1"); !errors.Is(err, ErrBadCheckID) || len(fake.tables) != 0 {
		t.Errorf("FailCheck = %v, %d calls; want %v without a call", err, len(fake.tables), ErrBadCheckID)
	}
}
