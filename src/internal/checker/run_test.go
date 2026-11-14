package checker

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/aws/aws-durable-execution-sdk-go/durable"
	"github.com/aws/aws-durable-execution-sdk-go/durable/durabletest"

	"github.com/JairJosafath/mcp-customs/src/internal/store"
	"github.com/JairJosafath/mcp-customs/src/internal/verdict"
)

var npm = store.Submission{Kind: "npm", Ref: "weather-mcp@1.0.0"}

func TestHandlerCreatesTheCheckAsRunningThenRecordsTheStartFirst(t *testing.T) {
	rec := &memoryRecorder{}
	result, err := durabletest.NewLocalRunner(Handler(depsWith(rec))).RunUntilComplete(Input{CheckID: "c1", Submission: npm})
	if err != nil {
		t.Fatal(err)
	}
	out, err := durabletest.ResultAs[Output](result)
	if err != nil {
		t.Fatal(err)
	}
	if out != (Output{CheckID: "c1", Status: store.StatusDone, Verdict: verdict.Pass}) {
		t.Errorf("output = %+v", out)
	}
	if len(rec.created) != 1 {
		t.Fatalf("created %d checks, want 1: %+v", len(rec.created), rec.created)
	}
	check := rec.created[0]
	if check.ID != "c1" || check.Status != store.StatusRunning || check.Submission != npm || check.ExecutionARN == "" {
		t.Errorf("created %+v, want c1 running with its submission and execution ARN", check)
	}
	first := store.Step{Seq: 1, Name: "start", Summary: "The check started.", Findings: []store.Finding{}}
	if len(rec.steps) == 0 || !reflect.DeepEqual(rec.steps[0], first) || rec.stepsOf[0] != "c1" {
		t.Errorf("first step %+v, want %+v of c1", rec.steps, first)
	}
	for _, name := range []string{"record-check", "step-0001"} {
		op := result.Operation(name)
		if op == nil || op.Type != "STEP" || op.Status != "SUCCEEDED" {
			t.Errorf("operation %s = %+v, want a succeeded step", name, op)
		}
	}
}

func TestHandlerRefusesABadEventBeforeRecordingAnything(t *testing.T) {
	for name, tc := range map[string]struct {
		in   Input
		want error
	}{
		"no check id":    {Input{Submission: npm}, ErrBadCheckID},
		"a bad check id": {Input{CheckID: "CHECK#c1", Submission: npm}, ErrBadCheckID},
		"no kind":        {Input{CheckID: "c1", Submission: store.Submission{Ref: "x@1"}}, ErrBadSubmission},
		"another kind":   {Input{CheckID: "c1", Submission: store.Submission{Kind: "cargo", Ref: "x@1"}}, ErrBadSubmission},
		"no ref":         {Input{CheckID: "c1", Submission: store.Submission{Kind: "npm"}}, ErrBadSubmission},
		"a ref too long": {Input{CheckID: "c1", Submission: store.Submission{Kind: "npm", Ref: strings.Repeat("a", maxRefLength+1)}}, ErrBadSubmission},
	} {
		rec := &memoryRecorder{}
		result, err := durabletest.NewLocalRunner(Handler(depsWith(rec))).RunUntilComplete(tc.in)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if result.Status != durabletest.Failed || result.Error == nil || result.Error.Message != tc.want.Error() {
			t.Errorf("%s: status %s, error %+v; want failed with %v", name, result.Status, result.Error, tc.want)
		}
		if len(rec.checks)+len(rec.steps) != 0 {
			t.Errorf("%s: recorded %+v and %+v", name, rec.checks, rec.steps)
		}
	}
}

func TestHandlerFailsWithTheErrorWhenTheStoreFails(t *testing.T) {
	outage := errors.New("put check into table customs: service unavailable")
	for name, tc := range map[string]struct {
		rec    *memoryRecorder
		want   []string
		checks int
	}{
		"the check can't be recorded": {
			&memoryRecorder{putErr: outage},
			[]string{"record check c1 as running", outage.Error()},
			0,
		},
		"the first step can't be recorded": {
			&memoryRecorder{stepErr: outage},
			[]string{"record step 1 (start) of check c1", outage.Error()},
			1,
		},
	} {
		result, err := durabletest.NewLocalRunner(Handler(depsWith(tc.rec))).RunUntilComplete(Input{CheckID: "c1", Submission: npm})
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if result.Status != durabletest.Failed || result.Error == nil {
			t.Fatalf("%s: status %s, error %+v; want failed", name, result.Status, result.Error)
		}
		for _, want := range tc.want {
			if !strings.Contains(result.Error.Message, want) {
				t.Errorf("%s: error %q, want it to say %q", name, result.Error.Message, want)
			}
		}
		if len(tc.rec.steps) != 0 {
			t.Errorf("%s: wrote STEP# items %+v", name, tc.rec.steps)
		}
		if len(tc.rec.checks) != tc.checks {
			t.Errorf("%s: recorded checks %+v, want %d", name, tc.rec.checks, tc.checks)
		}
	}
}

func TestHandlerFinishesWhenARetriedStepFindsTheCheckItCreated(t *testing.T) {
	rec := &memoryRecorder{loseFirstReply: true}
	result, err := durabletest.NewLocalRunner(Handler(depsWith(rec))).RunUntilComplete(Input{CheckID: "c1", Submission: npm})
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != durabletest.Succeeded {
		t.Fatalf("status %s, error %+v; want succeeded", result.Status, result.Error)
	}
	if rec.puts != 2 || len(rec.checks) != 1 || rec.steps[0].Name != "start" {
		t.Errorf("%d creates made %d checks, then steps %v; want 2, 1, and the start first", rec.puts, len(rec.checks), rec.stepNames())
	}
}

func TestHandlerRefusesACheckAnotherExecutionCreated(t *testing.T) {
	theirs := store.Check{ID: "c1", Submission: npm, Status: store.StatusDone, Verdict: "pass", ExecutionARN: "arn:another-execution"}
	rec := &memoryRecorder{checks: []store.Check{theirs}}
	result, err := durabletest.NewLocalRunner(Handler(depsWith(rec))).RunUntilComplete(Input{CheckID: "c1", Submission: npm})
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != durabletest.Failed || result.Error == nil || !strings.Contains(result.Error.Message, store.ErrCheckExists.Error()) {
		t.Errorf("status %s, error %+v; want failed with %v", result.Status, result.Error, store.ErrCheckExists)
	}
	if !reflect.DeepEqual(rec.checks, []store.Check{theirs}) || len(rec.steps) != 0 {
		t.Errorf("recorded %+v and steps %+v, want the other execution's check alone", rec.checks, rec.steps)
	}
}

// The handler is the SDK's handler type, which durable.Start takes.
var _ durable.Handler[Input, Output] = Handler(Deps{})

// depsWith is a clean server's world, writing to rec.
func depsWith(rec *memoryRecorder) Deps {
	w := newWorld(cleanServer())
	w.rec = rec
	return w.deps()
}
