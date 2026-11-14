package checker

import (
	"slices"
	"strings"
	"testing"

	"github.com/JairJosafath/mcp-customs/src/internal/verdict"
)

func TestAnInvestigationMovesTheClockReadsTheSourceAndEndsAtAVerdict(t *testing.T) {
	srv := cleanServer()
	srv.sources = map[string]string{"dist/index.js": "setTimeout(check, 30 * 86400e3); fetch('https://api.open-meteo.com')"}
	w := newWorld(srv)
	w.judge.moves = []string{"move_clock", "move_read_source", "move_done_pass"}
	_, out, _ := runToEnd(t, w, npm)
	if out.Verdict != verdict.Pass {
		t.Errorf("verdict %s, want the judge's pass", out.Verdict)
	}
	paths := w.paths()
	clock, source, seal := slices.Index(paths, "/clock"), slices.Index(paths, "/source"), slices.Index(paths, "/seal")
	if clock < 0 || source < clock || seal < source {
		t.Errorf("harness calls %v, want /clock, then /source, then /seal", paths)
	}
	if n := len(w.judge.asked); n != 3 {
		t.Fatalf("the judge was asked %d times, want 3", n)
	}
	turns := w.judge.asked[2].Turns
	if len(turns) != 2 || !strings.Contains(turns[0].Outcome, "2026-12-14") || !strings.Contains(turns[1].Outcome, "api.open-meteo.com") {
		t.Errorf("turns %+v, want the clock in force, then the source's text", turns)
	}
}

func TestTheJudgeIsToldWhenTheServersRuntimeCantSeeTheMovedClock(t *testing.T) {
	srv := cleanServer()
	srv.clockApplies = "no"
	w := newWorld(srv)
	w.judge.moves = []string{"move_clock", "move_done_pass"}
	runToEnd(t, w, npm)
	if turns := w.judge.asked[1].Turns; len(turns) != 1 || !strings.Contains(turns[0].Outcome, "does NOT see the moved clock") {
		t.Errorf("turns %+v, want the judge told the move isn't seen", turns)
	}
}
