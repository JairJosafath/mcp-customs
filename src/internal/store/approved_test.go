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
		if err := store.PutApproved(t.Context(), a, false); err != nil {
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
	if err := store.PutApproved(t.Context(), Approved{Kind: "go", Name: "example.com/mail", Version: "v1.0.0", CheckID: "c0"}, false); err != nil {
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
		if err := store.PutApproved(t.Context(), a, false); !errors.Is(err, ErrBadPackage) {
			t.Errorf("%s: PutApproved = %v, want %v", name, err, ErrBadPackage)
		}
	}
}

func TestTheNewestPolledVersionWinsWhateverOrderTheRechecksFinishIn(t *testing.T) {
	mail := func(version, checkID string) Approved {
		return Approved{Kind: "go", Name: "example.com/mail", Version: version, CheckID: checkID, ToolListHash: "t"}
	}
	// Two re-checks race from one approval (v1.0.0), of v1.0.1 and v1.0.2.
	// Whichever finishes first, the newer version — the one the poller
	// polled last — must end up approved, and the older one must be a no-op.
	for _, order := range [][]string{{"v1.0.1", "v1.0.2"}, {"v1.0.2", "v1.0.1"}} {
		fake := newFakeDynamo()
		store := New(fake, "customs")
		if err := store.PutApproved(t.Context(), mail("v1.0.0", "c0"), false); err != nil {
			t.Fatal(err)
		}
		// The poller starts the re-checks of v1.0.1 then v1.0.2; each start
		// advances the newest polled version. v1.0.2 is newest.
		for _, v := range []string{"v1.0.1", "v1.0.2"} {
			if err := store.MarkPolled(t.Context(), "go", "example.com/mail", v); err != nil {
				t.Fatal(err)
			}
		}
		// The re-checks finish in this round's order.
		for _, v := range order {
			if err := store.PutApproved(t.Context(), mail(v, "check-"+v), true); err != nil {
				t.Errorf("order %v: PutApproved(%s) = %v, want a silent no-op at worst", order, v, err)
			}
		}
		got, err := store.ListApproved(t.Context())
		if err != nil || len(got) != 1 || got[0].Version != "v1.0.2" || got[0].CheckID != "check-v1.0.2" {
			t.Errorf("order %v: ListApproved = %+v, %v; want v1.0.2 approved whatever the order", order, got, err)
		}
	}
}

func TestAFreshApprovalReplacesWhateverIsThere(t *testing.T) {
	store := New(newFakeDynamo(), "customs")
	mail := func(version, checkID string) Approved {
		return Approved{Kind: "go", Name: "example.com/mail", Version: version, CheckID: checkID, ToolListHash: "t"}
	}
	if err := store.PutApproved(t.Context(), mail("v1.0.0", "c0"), false); err != nil {
		t.Fatal(err)
	}
	// A fresh (unconditional) approval replaces it, polled and all.
	if err := store.PutApproved(t.Context(), mail("v2.0.0", "c9"), false); err != nil {
		t.Fatal(err)
	}
	if got, _ := store.ListApproved(t.Context()); len(got) != 1 || got[0].Version != "v2.0.0" || got[0].Polled != "v2.0.0" {
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
