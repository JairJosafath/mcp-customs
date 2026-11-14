package checker

import (
	"context"
	"sync"
	"testing"

	"github.com/aws/aws-durable-execution-sdk-go/durable/durabletest"

	"github.com/JairJosafath/mcp-customs/src/internal/verdict"
)

// lateJudge answers ErrNoTime to the first call of each of its methods,
// as a judge asked too late in an invocation does, then asks judge.
type lateJudge struct {
	judge Judge
	mu    sync.Mutex
	asked map[string]bool
}

func (l *lateJudge) late(method string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	first := !l.asked[method]
	l.asked[method] = true
	return first
}

func (l *lateJudge) WriteProbes(ctx context.Context, req ProbeRequest) ([]ProbeArgs, error) {
	if l.late("probes") {
		return nil, ErrNoTime
	}
	return l.judge.WriteProbes(ctx, req)
}

func (l *lateJudge) Judge(ctx context.Context, e Evidence) (Judgement, error) {
	if l.late("judge") {
		return Judgement{}, ErrNoTime
	}
	return l.judge.Judge(ctx, e)
}

func (l *lateJudge) Next(ctx context.Context, inv Investigation) (Move, error) {
	if l.late("next") {
		return Move{}, ErrNoTime
	}
	return l.judge.Next(ctx, inv)
}

func TestAJudgeAskedTooLateIsAskedAgainNotFailed(t *testing.T) {
	w := newWorld(cleanServer())
	deps := w.deps()
	deps.Judge = &lateJudge{judge: w.judge, asked: map[string]bool{}}
	result, err := durabletest.NewLocalRunner(Handler(deps)).RunUntilComplete(Input{CheckID: "c1", Submission: npm})
	if err != nil {
		t.Fatal(err)
	}
	out, err := durabletest.ResultAs[Output](result)
	if err != nil || out.Verdict != verdict.Pass {
		t.Errorf("output %+v, %v; want the pass of a judge asked again in a fresh invocation", out, err)
	}
	if len(w.judge.requests) != 1 || len(w.judge.evidence) != 1 {
		t.Errorf("probe requests %d, judgements %d; want each asked once more, once", len(w.judge.requests), len(w.judge.evidence))
	}
}
