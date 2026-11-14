package checker

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/aws/aws-durable-execution-sdk-go/durable"
	"github.com/aws/aws-durable-execution-sdk-go/durable/durabletest"

	"github.com/JairJosafath/mcp-customs/src/internal/store"
	"github.com/JairJosafath/mcp-customs/src/internal/verdict"
)

// These tests answer past the decoders, which refuse first, to reach the
// checks behind them: each fails if its check is removed.

func TestTheJudgeStepDropsAnInternalHostTheJudgeExpects(t *testing.T) {
	w := newWorld(cleanServer())
	w.judge.judgeAnswer = &Judgement{Verdict: verdict.Pass, ExpectedHosts: []string{"api.open-meteo.com", "metadata.google.internal"}}
	_, out, _ := runToEnd(t, w, npm)
	var allowed []string
	for _, c := range w.vms.Calls() {
		if c.Request.Path == "/allow" {
			body, _ := c.Request.Body.(map[string]any)
			allowed, _ = body["hosts"].([]string)
		}
	}
	if !slices.Equal(allowed, []string{"api.open-meteo.com"}) || out.Verdict != verdict.Pass {
		t.Errorf("allowed %v, verdict %s; want only the public host allowed, and a pass", allowed, out.Verdict)
	}
}

func TestTheAllowActionRefusesAnInternalHost(t *testing.T) {
	w := newWorld(cleanServer())
	handler := func(ctx durable.Context, args string) (string, error) {
		r := &run{deps: w.deps(), in: Input{CheckID: "c1"}}
		return "", r.do(ctx, ActAllow, json.RawMessage(args))
	}
	for _, host := range []string{"metadata.google.internal", "169.254.169.254", "localhost"} {
		args, _ := json.Marshal(allowArgs{Hosts: []string{"api.open-meteo.com", host}})
		result, err := durabletest.NewLocalRunner(handler).RunUntilComplete(string(args))
		if err != nil {
			t.Fatal(err)
		}
		if result.Status != durabletest.Failed || !strings.Contains(result.Error.Message, ErrBadArguments.Error()) || slices.Contains(w.paths(), "/allow") {
			t.Errorf("%s: status %s, error %+v, harness calls %v; want refused before /allow", host, result.Status, result.Error, w.paths())
		}
	}
}

func TestAMoveTheJudgeMayNotPickEndsTheInvestigationAtReview(t *testing.T) {
	w := newWorld(cleanServer())
	w.judge.moveAnswer = &Move{Action: "shell", Arguments: json.RawMessage(`{}`)}
	_, out, _ := runToEnd(t, w, npm)
	picked := slices.ContainsFunc(w.rec.steps, func(s store.Step) bool {
		return s.Name == "investigate" && strings.Contains(s.Summary, "an action it may not")
	})
	if out.Verdict != verdict.Review || !picked {
		t.Errorf("verdict %s, steps %v; want review, recorded as an action the judge may not pick", out.Verdict, w.rec.stepNames())
	}
}
