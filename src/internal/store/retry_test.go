package store

import (
	"errors"
	"testing"
)

func TestARetryIsAskedOnlyForTheNewestPolledVersionAndClearedOnce(t *testing.T) {
	fake := newFakeDynamo()
	store := New(fake, "customs")
	if marked, err := store.MarkRetry(t.Context(), "go", "example.com/mail", "v1.0.1"); err != nil || marked {
		t.Errorf("a package never approved: MarkRetry = %v, %v; want false, nil", marked, err)
	}
	if err := approve(t.Context(), store, Approved{Kind: "go", Name: "example.com/mail", Version: "v1.0.0", CheckID: "c0"}, false); err != nil {
		t.Fatal(err)
	}
	for _, v := range []string{"v1.0.1", "v1.0.2"} {
		if err := store.MarkPolled(t.Context(), "go", "example.com/mail", v); err != nil {
			t.Fatal(err)
		}
	}
	if marked, err := store.MarkRetry(t.Context(), "go", "example.com/mail", "v1.0.1"); err != nil || marked {
		t.Errorf("an overtaken version: MarkRetry = %v, %v; want false, nil", marked, err)
	}
	for range 2 {
		if marked, err := store.MarkRetry(t.Context(), "go", "example.com/mail", "v1.0.2"); err != nil || !marked {
			t.Errorf("the newest polled version: MarkRetry = %v, %v; want true, nil", marked, err)
		}
	}
	got, err := store.ListApproved(t.Context())
	if err != nil || len(got) != 1 || got[0].Retry != "v1.0.2" {
		t.Fatalf("ListApproved = %+v, %v; want a retry of v1.0.2", got, err)
	}
	if err := store.ClearRetry(t.Context(), "go", "example.com/mail", "v1.0.1"); err != nil {
		t.Errorf("clearing another version = %v, want a no-op", err)
	}
	if got, _ := store.ListApproved(t.Context()); got[0].Retry != "v1.0.2" {
		t.Errorf("clearing another version removed the ask: %+v", got)
	}
	for range 2 {
		if err := store.ClearRetry(t.Context(), "go", "example.com/mail", "v1.0.2"); err != nil {
			t.Errorf("ClearRetry = %v, want nil, and nil again", err)
		}
	}
	if got, _ := store.ListApproved(t.Context()); got[0].Retry != "" || got[0].Polled != "v1.0.2" {
		t.Errorf("after ClearRetry: %+v, want no retry and v1.0.2 polled", got)
	}
}

func TestARetryRefusesAPackageItCantKey(t *testing.T) {
	store := New(newFakeDynamo(), "customs")
	if _, err := store.MarkRetry(t.Context(), "npm#x", "mail", "1"); !errors.Is(err, ErrBadPackage) {
		t.Errorf("MarkRetry = %v, want %v", err, ErrBadPackage)
	}
	if err := store.ClearRetry(t.Context(), "npm", "mail", ""); !errors.Is(err, ErrBadPackage) {
		t.Errorf("ClearRetry = %v, want %v", err, ErrBadPackage)
	}
}
