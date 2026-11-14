package store

import (
	"errors"
	"reflect"
	"testing"
)

func TestStoreKeepsOneApprovalAPackageAndListsThemAll(t *testing.T) {
	fake := newFakeDynamo()
	store := New(fake, "customs")
	for _, a := range []Approved{
		{Kind: "go", Name: "example.com/mail", Version: "v1.0.0", CheckID: "c0", ToolListHash: "t0"},
		{Kind: "npm", Name: "@acme/weather-mcp", Version: "1.0.0", CheckID: "c1", ToolListHash: "t1"},
		{Kind: "go", Name: "example.com/mail", Version: "v1.0.1", CheckID: "c2", ToolListHash: "t0"},
	} {
		if err := store.PutApproved(t.Context(), a, ""); err != nil {
			t.Fatal(err)
		}
	}
	if _, ok := fake.items[[2]string{"APPROVED", "go#example.com/mail"}]; !ok {
		t.Errorf("no item at APPROVED, go#example.com/mail: %v", fake.items)
	}
	got, err := store.ListApproved(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	want := []Approved{
		{Kind: "go", Name: "example.com/mail", Version: "v1.0.1", CheckID: "c2", ToolListHash: "t0", Polled: "v1.0.1"},
		{Kind: "npm", Name: "@acme/weather-mcp", Version: "1.0.0", CheckID: "c1", ToolListHash: "t1", Polled: "1.0.0"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ListApproved = %+v, want the latest approval of each package, %+v", got, want)
	}
}

func TestStoreMarksAPackagePolledOnlyWhenItWasApproved(t *testing.T) {
	fake := newFakeDynamo()
	store := New(fake, "customs")
	if err := store.MarkPolled(t.Context(), "go", "example.com/mail", "v1.0.1"); !errors.Is(err, ErrNoApproved) {
		t.Errorf("marking a package never approved = %v, want %v", err, ErrNoApproved)
	}
	if len(fake.items) != 0 {
		t.Errorf("made %v", fake.items)
	}
	if err := store.PutApproved(t.Context(), Approved{Kind: "go", Name: "example.com/mail", Version: "v1.0.0", CheckID: "c0"}, ""); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := store.MarkPolled(t.Context(), "go", "example.com/mail", "v1.0.1"); err != nil {
			t.Fatal(err)
		}
	}
	got, err := store.ListApproved(t.Context())
	if err != nil || len(got) != 1 || got[0].Polled != "v1.0.1" || got[0].Version != "v1.0.0" {
		t.Errorf("ListApproved = %+v, %v; want v1.0.0 approved and v1.0.1 polled", got, err)
	}
}

func TestStoreRefusesAPackageItCantKey(t *testing.T) {
	store := New(newFakeDynamo(), "customs")
	for name, a := range map[string]Approved{
		"no kind":      {Name: "mail", Version: "1"},
		"no name":      {Kind: "npm", Version: "1"},
		"no version":   {Kind: "npm", Name: "mail"},
		"a # the kind": {Kind: "npm#x", Name: "mail", Version: "1"},
	} {
		if err := store.PutApproved(t.Context(), a, ""); !errors.Is(err, ErrBadPackage) {
			t.Errorf("%s: PutApproved = %v, want %v", name, err, ErrBadPackage)
		}
	}
}

func TestARechecksApprovalDoesNotPullBackANewerOneAlreadyApproved(t *testing.T) {
	fake := newFakeDynamo()
	store := New(fake, "customs")
	mail := func(version, checkID string) Approved {
		return Approved{Kind: "go", Name: "example.com/mail", Version: version, CheckID: checkID, ToolListHash: "t"}
	}
	// v1.0.0 is approved (c0), then v1.0.2's re-check of c0 advances it.
	if err := store.PutApproved(t.Context(), mail("v1.0.0", "c0"), ""); err != nil {
		t.Fatal(err)
	}
	if err := store.PutApproved(t.Context(), mail("v1.0.2", "c2"), "c0"); err != nil {
		t.Fatal(err)
	}
	// v1.0.1's re-check, also based on c0, finishes late: its approval is a
	// no-op (no error), and the newer v1.0.2 stays approved.
	if err := store.PutApproved(t.Context(), mail("v1.0.1", "c1"), "c0"); err != nil {
		t.Errorf("a superseded re-check's approval = %v, want a silent no-op", err)
	}
	got, err := store.ListApproved(t.Context())
	if err != nil || len(got) != 1 || got[0].Version != "v1.0.2" || got[0].CheckID != "c2" {
		t.Errorf("ListApproved = %+v, %v; want v1.0.2 (c2) kept", got, err)
	}
	// A fresh approval (no fromCheckID) still replaces whatever is there.
	if err := store.PutApproved(t.Context(), mail("v2.0.0", "c9"), ""); err != nil {
		t.Fatal(err)
	}
	if got, _ := store.ListApproved(t.Context()); got[0].Version != "v2.0.0" {
		t.Errorf("a fresh approval did not replace: %+v", got)
	}
}

func TestSplitRefCutsAtTheLastAt(t *testing.T) {
	for ref, want := range map[string][3]any{
		"weather-mcp@1.0.0":         {"weather-mcp", "1.0.0", true},
		"@acme/weather-mcp@1.0.0":   {"@acme/weather-mcp", "1.0.0", true},
		"example.com/mail@v1.0.1":   {"example.com/mail", "v1.0.1", true},
		"weather-mcp":               {"", "", false},
		"weather-mcp@":              {"", "", false},
		"@1.0.0":                    {"", "", false},
		"https://mcp.example.com/x": {"", "", false},
	} {
		name, version, ok := SplitRef(ref)
		if got := [3]any{name, version, ok}; got != want {
			t.Errorf("SplitRef(%q) = %v, want %v", ref, got, want)
		}
	}
}
