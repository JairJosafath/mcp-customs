package runstats

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

func readFixture(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return string(b)
}

func TestTheFixtureRunsPrintTheExpectedNumbers(t *testing.T) {
	rows, err := ParseRuns(strings.NewReader(readFixture(t, "runs.md")))
	if err != nil {
		t.Fatalf("ParseRuns: %v", err)
	}
	st, err := Compute(rows, ParseMerges(readFixture(t, "gitlog.txt")))
	if err != nil {
		t.Fatalf("Compute: %v", err)
	}
	var out bytes.Buffer
	st.Write(&out, Source{RunsPath: "docs/runs.md", RunsCommit: "aaaaaaa", Head: "bbbbbbb"})
	if want := readFixture(t, "stats.txt"); out.String() != want {
		t.Errorf("printed\n%s\nwant\n%s", out.String(), want)
	}
}

func TestASessionsCostIsItsTotalOnceOrElseTheSumOfItsRounds(t *testing.T) {
	tests := []struct {
		name      string
		rows      []Row
		wantCents int
		wantOK    bool
	}{
		{"per-round costs add up", []Row{
			{Session: "s", CostCents: 214, HasCost: true},
			{Session: "s", CostCents: 190, HasCost: true},
		}, 404, true},
		{"a total replaces the rounds before it", []Row{
			{Session: "s", CostCents: 638, HasCost: true},
			{Session: "s", CostCents: 774, HasCost: true, Total: true},
		}, 774, true},
		{"the last total counts", []Row{
			{Session: "s", CostCents: 500, HasCost: true, Total: true},
			{Session: "s", CostCents: 900, HasCost: true, Total: true},
		}, 900, true},
		{"another session's cost is not this one's", []Row{
			{Session: "s", CostCents: 100, HasCost: true},
			{Session: "t", CostCents: 999, HasCost: true, Total: true},
		}, 100, true},
		{"no cost reported", []Row{{Session: "s"}}, 0, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cents, ok := sessionCost(tt.rows, "s")
			if cents != tt.wantCents || ok != tt.wantOK {
				t.Errorf("sessionCost = %d, %v; want %d, %v", cents, ok, tt.wantCents, tt.wantOK)
			}
		})
	}
}

func TestARowThatCannotBeReadIsAnError(t *testing.T) {
	const head = "| Issue | Role | Session | Started (UTC) | Rounds | Result | Cost |\n| - | - | - | - | - | - | - |\n"
	tests := []struct {
		name, row, want string
	}{
		{"unknown role", "| #1 | tester | session_01A | 2026-11-14 06:27 | 1 | x | |", "unknown role"},
		{"no issue", "| none | implementer | session_01A | 2026-11-14 06:27 | 1 | x | |", "no issue"},
		{"rounds not a number", "| #1 | implementer | session_01A | 2026-11-14 06:27 | two | x | |", "rounds"},
		{"cost not in dollars", "| #1 | implementer | session_01A | 2026-11-14 06:27 | 1 | x | 4 EUR |", "cost"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseRuns(strings.NewReader(head + tt.row + "\n"))
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("ParseRuns error = %v, want one naming %q", err, tt.want)
			}
		})
	}
}

func TestARowForTwoIssuesThatNamesAMergedPRIsAnError(t *testing.T) {
	rows := []Row{{Issues: []int{1, 2}, Role: RoleImplementer, Session: "s", Result: "PR #10"}}
	if _, err := Compute(rows, []int{10}); err == nil {
		t.Error("Compute named no error for a PR whose issue is unclear")
	}
}

func TestAMergedPRNoRowNamesIsListedAsUnmapped(t *testing.T) {
	rows := []Row{{Issues: []int{1}, Role: RoleImplementer, Session: "s", Round: 1, Result: "PR #10"}}
	st, err := Compute(rows, []int{10, 12})
	if err != nil {
		t.Fatalf("Compute: %v", err)
	}
	if len(st.Unmapped) != 1 || st.Unmapped[0] != 12 {
		t.Errorf("Unmapped = %v, want [12]", st.Unmapped)
	}
	if len(st.MergedIssues) != 1 || st.MergedIssues[0].Number != 1 {
		t.Errorf("MergedIssues = %v, want #1 alone", st.MergedIssues)
	}
}

func TestOnlySquashCommitsCountAsMerges(t *testing.T) {
	got := ParseMerges("fix: b (#12)\ndocs(runs): #12 merged\nfeat: c (#13) and more\nMerge branch 'main'\nfeat: a (#11)\n")
	if len(got) != 2 || got[0] != 11 || got[1] != 12 {
		t.Errorf("ParseMerges = %v, want [11 12]", got)
	}
}

func TestASessionUnderTwoRolesIsAnError(t *testing.T) {
	rows := []Row{
		{Issues: []int{1}, Role: RoleImplementer, Session: "s"},
		{Issues: []int{1}, Role: RoleReviewer, Session: "s"},
	}
	if _, err := Compute(rows, nil); err == nil {
		t.Error("Compute named no error for a session under two roles")
	}
}
