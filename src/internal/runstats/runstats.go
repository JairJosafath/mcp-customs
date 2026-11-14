// Package runstats counts what docs/runs.md and git log say about the
// build: the sessions, the pull requests merged, the review rounds of each
// merged issue and the cost the sessions reported. docs/results.md quotes
// what it prints; hack/runs-stats runs it.
package runstats

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// The roles a session plays in runs.md. A merge row has no session.
const (
	RoleImplementer = "implementer"
	RoleReviewer    = "reviewer"
	roleMerge       = "merge"
)

// Row is one row of the table in runs.md.
type Row struct {
	Issues  []int
	Role    string
	Session string // empty when the row names no session ID
	Started string
	// Round is the Rounds column's number, 0 when empty; Plus marks a
	// round written "1+", one with a push after it that no round counts.
	Round  int
	Plus   bool
	Result string
	// CostCents is the Cost column in cents; HasCost says the cell had
	// one. Total marks a "$N total" cell: the session's whole cost so
	// far, not this row's.
	CostCents int
	HasCost   bool
	Total     bool
}

var (
	sessionRE = regexp.MustCompile(`^session_[A-Za-z0-9]+$`)
	issueRE   = regexp.MustCompile(`#(\d+)`)
	roundRE   = regexp.MustCompile(`^(\d+)(\+?)$`)
	costRE    = regexp.MustCompile(`^\$(\d+)\.(\d{2})( total\b.*)?$`)
	prRE      = regexp.MustCompile(`\bPR #(\d+)`)
	squashRE  = regexp.MustCompile(`\(#(\d+)\)$`)
)

// header is the first cell of the table's header row.
const header = "Issue"

// ParseRuns reads the table in runs.md, skipping everything around it.
func ParseRuns(r io.Reader) ([]Row, error) {
	var rows []Row
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	line := 0
	for sc.Scan() {
		line++
		cells, ok := tableCells(sc.Text())
		if !ok || cells[0] == header || strings.Trim(cells[0], "- ") == "" {
			continue
		}
		row, err := parseRow(cells)
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", line, err)
		}
		rows = append(rows, row)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("read runs.md: %w", err)
	}
	if len(rows) == 0 {
		return nil, errors.New("runs.md has no table rows")
	}
	return rows, nil
}

// columns is how many cells a row of the table has.
const columns = 7

func tableCells(line string) ([]string, bool) {
	line = strings.TrimSpace(line)
	if !strings.HasPrefix(line, "|") || !strings.HasSuffix(line, "|") {
		return nil, false
	}
	parts := strings.Split(line[1:len(line)-1], "|")
	if len(parts) != columns {
		return nil, false
	}
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	return parts, true
}

func parseRow(c []string) (Row, error) {
	row := Row{Role: c[1], Started: c[3], Result: c[5]}
	switch row.Role {
	case RoleImplementer, RoleReviewer, roleMerge:
	default:
		return Row{}, fmt.Errorf("unknown role %q", row.Role)
	}
	for _, m := range issueRE.FindAllStringSubmatch(c[0], -1) {
		n, err := strconv.Atoi(m[1])
		if err != nil {
			return Row{}, fmt.Errorf("issue %q: %w", m[0], err)
		}
		row.Issues = append(row.Issues, n)
	}
	if len(row.Issues) == 0 {
		return Row{}, fmt.Errorf("no issue in %q", c[0])
	}
	if sessionRE.MatchString(c[2]) {
		row.Session = c[2]
	}
	if c[4] != "" {
		m := roundRE.FindStringSubmatch(c[4])
		if m == nil {
			return Row{}, fmt.Errorf("rounds %q is not a number", c[4])
		}
		n, err := strconv.Atoi(m[1])
		if err != nil {
			return Row{}, fmt.Errorf("rounds %q: %w", c[4], err)
		}
		row.Round, row.Plus = n, m[2] == "+"
	}
	if c[6] != "" {
		m := costRE.FindStringSubmatch(c[6])
		if m == nil {
			return Row{}, fmt.Errorf("cost %q is not $N.NN or $N.NN total", c[6])
		}
		dollars, err := strconv.Atoi(m[1])
		if err != nil {
			return Row{}, fmt.Errorf("cost %q: %w", c[6], err)
		}
		cents, err := strconv.Atoi(m[2])
		if err != nil {
			return Row{}, fmt.Errorf("cost %q: %w", c[6], err)
		}
		row.CostCents, row.HasCost, row.Total = dollars*100+cents, true, m[3] != ""
	}
	return row, nil
}

// ParseMerges reads `git log --first-parent --format=%s` and returns the
// pull requests merged, oldest first: each squash commit's subject ends in
// its pull request's number, "(#12)".
func ParseMerges(log string) []int {
	var prs []int
	for line := range strings.Lines(log) {
		m := squashRE.FindStringSubmatch(strings.TrimSpace(line))
		if m == nil {
			continue
		}
		n, err := strconv.Atoi(m[1])
		if err != nil {
			continue
		}
		prs = append(prs, n)
	}
	slices.Reverse(prs)
	return prs
}

// Session is one session ID's rows, added up.
type Session struct {
	ID    string
	Roles []string
	// CostCents is the session's cost: its last "total" cell when it has
	// one, else the sum of its rows' costs. HasCost is false when no row
	// of it reported one.
	CostCents int
	HasCost   bool
}

// Issue is a merged pull request's issue and how many review rounds it
// took: the highest Rounds of its implementer and reviewer rows.
type Issue struct {
	Number int
	PR     int
	Rounds int
	Plus   bool
}

// Label is the rounds as runs.md writes them: "3", or "1+".
func (i Issue) Label() string {
	if i.Plus {
		return strconv.Itoa(i.Rounds) + "+"
	}
	return strconv.Itoa(i.Rounds)
}

// Stats is everything Write prints.
type Stats struct {
	Sessions []Session
	// NoSessionRows counts implementer and reviewer rows with no session ID.
	NoSessionRows int
	IssuesWorked  int
	Merged        []int
	// MergedIssues are the merged pull requests' issues, in merge order;
	// Unmapped the merged pull requests no row of runs.md names.
	MergedIssues     []Issue
	Unmapped         []int
	FirstStart       string
	LastStart        string
	RowsWithoutStart int
}

// Compute adds up the rows of runs.md and the pull requests git log merged.
func Compute(rows []Row, merged []int) (Stats, error) {
	st := Stats{Merged: merged}
	if err := st.addSessions(rows); err != nil {
		return Stats{}, err
	}
	issues := map[int]bool{}
	for _, r := range rows {
		for _, n := range r.Issues {
			issues[n] = true
		}
		if r.Started == "" {
			st.RowsWithoutStart++
			continue
		}
		if st.FirstStart == "" || r.Started < st.FirstStart {
			st.FirstStart = r.Started
		}
		st.LastStart = max(st.LastStart, r.Started)
	}
	st.IssuesWorked = len(issues)
	prIssue, err := issueOfPR(rows, merged)
	if err != nil {
		return Stats{}, err
	}
	for _, pr := range merged {
		n, ok := prIssue[pr]
		if !ok {
			st.Unmapped = append(st.Unmapped, pr)
			continue
		}
		st.MergedIssues = append(st.MergedIssues, roundsOf(rows, n, pr))
	}
	return st, nil
}

func (st *Stats) addSessions(rows []Row) error {
	byID := map[string]*Session{}
	var order []string
	for _, r := range rows {
		if r.Role == roleMerge {
			if r.Session != "" {
				return fmt.Errorf("merge row for #%d names session %s", r.Issues[0], r.Session)
			}
			continue
		}
		if r.Session == "" {
			st.NoSessionRows++
			continue
		}
		s, ok := byID[r.Session]
		if !ok {
			s = &Session{ID: r.Session}
			byID[r.Session] = s
			order = append(order, r.Session)
		}
		if !slices.Contains(s.Roles, r.Role) {
			s.Roles = append(s.Roles, r.Role)
		}
	}
	for _, id := range order {
		s := byID[id]
		s.CostCents, s.HasCost = sessionCost(rows, id)
		st.Sessions = append(st.Sessions, *s)
	}
	return nil
}

// sessionCost is a session's last "total" cell when it has one, which
// already holds its rounds' costs, else the sum of its per-round costs.
func sessionCost(rows []Row, id string) (cents int, ok bool) {
	sum, total, hasTotal := 0, 0, false
	for _, r := range rows {
		if r.Session != id || !r.HasCost {
			continue
		}
		ok = true
		if r.Total {
			total, hasTotal = r.CostCents, true
			continue
		}
		sum += r.CostCents
	}
	if hasTotal {
		return total, ok
	}
	return sum, ok
}

// issueOfPR maps each merged pull request to the one issue whose rows name
// it, "PR #12".
func issueOfPR(rows []Row, merged []int) (map[int]int, error) {
	out := map[int]int{}
	for _, r := range rows {
		for _, m := range prRE.FindAllStringSubmatch(r.Result, -1) {
			pr, err := strconv.Atoi(m[1])
			if err != nil || !slices.Contains(merged, pr) {
				continue
			}
			if len(r.Issues) != 1 {
				return nil, fmt.Errorf("a row for %v names PR #%d: which issue it closes is unclear", r.Issues, pr)
			}
			if n, ok := out[pr]; ok && n != r.Issues[0] {
				return nil, fmt.Errorf("PR #%d is named in rows for #%d and #%d", pr, n, r.Issues[0])
			}
			out[pr] = r.Issues[0]
		}
	}
	return out, nil
}

func roundsOf(rows []Row, issue, pr int) Issue {
	is := Issue{Number: issue, PR: pr}
	for _, r := range rows {
		if r.Role == roleMerge || !slices.Contains(r.Issues, issue) {
			continue
		}
		if r.Round > is.Rounds || (r.Round == is.Rounds && r.Plus) {
			is.Rounds, is.Plus = r.Round, r.Plus
		}
	}
	return is
}

// Source names the commits the numbers were counted at.
type Source struct {
	RunsPath, RunsCommit, Head string
}

// Write prints the numbers, each line naming what it was counted from.
func (st Stats) Write(w io.Writer, src Source) {
	fmt.Fprintf(w, "Counted from %s as of commit %s, and git log --first-parent at %s.\n\n", src.RunsPath, src.RunsCommit, src.Head)

	impl, rev := st.byRole(RoleImplementer), st.byRole(RoleReviewer)
	fmt.Fprintf(w, "Sessions (distinct IDs, %s): %d: %d implementer, %d reviewer\n", src.RunsPath, len(st.Sessions), len(impl), len(rev))
	if st.NoSessionRows > 0 {
		fmt.Fprintf(w, "Implementer and reviewer rows with no session ID, not counted: %d\n", st.NoSessionRows)
	}
	fmt.Fprintf(w, "Issues with a row (%s): %d\n", src.RunsPath, st.IssuesWorked)
	if st.FirstStart != "" {
		fmt.Fprintf(w, "Rows started (%s): %s to %s UTC\n", src.RunsPath, st.FirstStart, st.LastStart)
	}

	all, allN := costOf(st.Sessions)
	implC, implN := costOf(impl)
	revC, revN := costOf(rev)
	fmt.Fprintf(w, "Cost reported (%s): %s from %d of %d sessions: %s from %d implementer, %s from %d reviewer\n",
		src.RunsPath, dollars(all), allN, len(st.Sessions), dollars(implC), implN, dollars(revC), revN)
	fmt.Fprintf(w, "Sessions that reported no cost: %d: %d implementer, %d reviewer\n",
		len(st.Sessions)-allN, len(impl)-implN, len(rev)-revN)

	fmt.Fprintf(w, "Pull requests merged (git log at %s): %d: %s\n", src.Head, len(st.Merged), hashes(st.Merged))
	if len(st.Unmapped) > 0 {
		fmt.Fprintf(w, "Merged pull requests no row of %s names: %s\n", src.RunsPath, hashes(st.Unmapped))
	}
	fmt.Fprintf(w, "Review rounds of the %d merged issues (%s):\n", len(st.MergedIssues), src.RunsPath)
	for _, label := range st.roundLabels() {
		var names []string
		for _, is := range st.MergedIssues {
			if is.Label() == label {
				names = append(names, fmt.Sprintf("#%d (PR #%d)", is.Number, is.PR))
			}
		}
		fmt.Fprintf(w, "  %s: %d: %s\n", label, len(names), strings.Join(names, ", "))
	}
}

func (st Stats) byRole(role string) []Session {
	var out []Session
	for _, s := range st.Sessions {
		if slices.Contains(s.Roles, role) {
			out = append(out, s)
		}
	}
	return out
}

func (st Stats) roundLabels() []string {
	var issues []Issue
	for _, is := range st.MergedIssues {
		if !slices.ContainsFunc(issues, func(o Issue) bool { return o.Label() == is.Label() }) {
			issues = append(issues, is)
		}
	}
	slices.SortFunc(issues, func(a, b Issue) int {
		if a.Rounds != b.Rounds {
			return a.Rounds - b.Rounds
		}
		if a.Plus == b.Plus {
			return 0
		}
		if a.Plus {
			return 1
		}
		return -1
	})
	labels := make([]string, len(issues))
	for i, is := range issues {
		labels[i] = is.Label()
	}
	return labels
}

func costOf(sessions []Session) (cents, reported int) {
	for _, s := range sessions {
		if s.HasCost {
			cents += s.CostCents
			reported++
		}
	}
	return cents, reported
}

func dollars(cents int) string {
	return fmt.Sprintf("$%d.%02d", cents/100, cents%100)
}

func hashes(ns []int) string {
	s := make([]string, len(ns))
	for i, n := range ns {
		s[i] = "#" + strconv.Itoa(n)
	}
	return strings.Join(s, " ")
}
