package store

import (
	"strings"
	"testing"
)

// supersedingWorld is approved check c0 of example.com/mail v1.0.0, with
// v1.0.1 then v1.0.2 polled: two re-checks race from one approval.
func supersedingWorld(t *testing.T) *Store {
	t.Helper()
	store := New(newFakeDynamo(), "customs")
	if err := store.PutCheck(t.Context(), Check{ID: "c0", Submission: Submission{Kind: "go", Ref: "example.com/mail@v1.0.0"}, Status: StatusDone, Verdict: "pass"}); err != nil {
		t.Fatal(err)
	}
	if err := approve(t.Context(), store, Approved{Kind: "go", Name: "example.com/mail", Version: "v1.0.0", CheckID: "c0"}, false); err != nil {
		t.Fatal(err)
	}
	for _, v := range []string{"v1.0.1", "v1.0.2"} {
		if err := store.MarkPolled(t.Context(), "go", "example.com/mail", v); err != nil {
			t.Fatal(err)
		}
	}
	return store
}

func superseding(version string) Superseding {
	return Superseding{RecheckID: "recheck-" + strings.ReplaceAll(version, ".", "-"), Kind: "go", Name: "example.com/mail", Version: version}
}

func TestTheNewestPolledVersionsRecheckKeepsTheSupersededLinkWhicheverEndsLast(t *testing.T) {
	for _, order := range [][]string{{"v1.0.1", "v1.0.2"}, {"v1.0.2", "v1.0.1"}} {
		store := supersedingWorld(t)
		for _, v := range order {
			marked, err := store.MarkSuperseded(t.Context(), "c0", superseding(v))
			if err != nil || marked != (v == "v1.0.2") {
				t.Errorf("order %v: MarkSuperseded(%s) = %v, %v; want marked only for the newest polled version", order, v, marked, err)
			}
		}
		c0, _, err := store.GetCheck(t.Context(), "c0")
		if err != nil || c0.SupersededBy != superseding("v1.0.2").RecheckID {
			t.Errorf("order %v: c0 %+v, %v; want it superseded by v1.0.2's re-check", order, c0, err)
		}
	}
}

func TestASupersededLinkIsLiftedOnlyByTheRecheckThatSetIt(t *testing.T) {
	store := supersedingWorld(t)
	newest := superseding("v1.0.2")
	if marked, err := store.MarkSuperseded(t.Context(), "c0", newest); err != nil || !marked {
		t.Fatalf("MarkSuperseded = %v, %v", marked, err)
	}
	if lifted, err := store.LiftSuperseded(t.Context(), "c0", superseding("v1.0.1").RecheckID); err != nil || lifted {
		t.Errorf("another re-check's lift = %v, %v; want false, nil", lifted, err)
	}
	if c0, _, _ := store.GetCheck(t.Context(), "c0"); c0.SupersededBy != newest.RecheckID {
		t.Errorf("c0 %+v, want the link kept", c0)
	}
	if lifted, err := store.LiftSuperseded(t.Context(), "c0", newest.RecheckID); err != nil || !lifted {
		t.Errorf("lift = %v, %v; want lifted", lifted, err)
	}
	if c0, _, _ := store.GetCheck(t.Context(), "c0"); c0.SupersededBy != "" {
		t.Errorf("c0 %+v, want no link", c0)
	}
}

func TestALiftRetriedAfterItCommittedStillAnswersLifted(t *testing.T) {
	// A retry of a lift whose reply was lost must still say so, or the
	// lifted event is never sent; another re-check's lift stays refused.
	store := supersedingWorld(t)
	newest := superseding("v1.0.2")
	if marked, err := store.MarkSuperseded(t.Context(), "c0", newest); err != nil || !marked {
		t.Fatalf("MarkSuperseded = %v, %v", marked, err)
	}
	for i := range 2 {
		if lifted, err := store.LiftSuperseded(t.Context(), "c0", newest.RecheckID); err != nil || !lifted {
			t.Errorf("lift %d = %v, %v; want lifted each time", i, lifted, err)
		}
	}
	if lifted, err := store.LiftSuperseded(t.Context(), "c0", superseding("v1.0.1").RecheckID); err != nil || lifted {
		t.Errorf("another re-check's lift = %v, %v; want false, nil", lifted, err)
	}
}

func TestALateLiftRetryLeavesANewerMark(t *testing.T) {
	store := supersedingWorld(t)
	older, newest := superseding("v1.0.2"), superseding("v1.0.3")
	if marked, err := store.MarkSuperseded(t.Context(), "c0", older); err != nil || !marked {
		t.Fatalf("MarkSuperseded = %v, %v", marked, err)
	}
	if lifted, err := store.LiftSuperseded(t.Context(), "c0", older.RecheckID); err != nil || !lifted {
		t.Fatalf("lift = %v, %v; want lifted", lifted, err)
	}
	if err := store.MarkPolled(t.Context(), "go", "example.com/mail", "v1.0.3"); err != nil {
		t.Fatal(err)
	}
	if marked, err := store.MarkSuperseded(t.Context(), "c0", newest); err != nil || !marked {
		t.Fatalf("MarkSuperseded = %v, %v", marked, err)
	}
	if lifted, err := store.LiftSuperseded(t.Context(), "c0", older.RecheckID); err != nil || lifted {
		t.Errorf("late retry of the older lift = %v, %v; want false, nil", lifted, err)
	}
	if c0, _, _ := store.GetCheck(t.Context(), "c0"); c0.SupersededBy != newest.RecheckID {
		t.Errorf("c0 %+v, want the newer link kept", c0)
	}
}

func TestAMarkOfACheckThatIsNotKeptChangesNothing(t *testing.T) {
	store := supersedingWorld(t)
	if marked, err := store.MarkSuperseded(t.Context(), "c9", superseding("v1.0.2")); err != nil || marked {
		t.Errorf("MarkSuperseded of a check not kept = %v, %v; want false, nil", marked, err)
	}
}
