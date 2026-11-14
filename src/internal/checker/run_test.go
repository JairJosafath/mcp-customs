package checker

import (
	"context"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/aws/aws-durable-execution-sdk-go/durable"
	"github.com/aws/aws-durable-execution-sdk-go/durable/durabletest"

	"github.com/JairJosafath/mcp-customs/src/internal/store"
)

// memoryRecorder keeps every write the handler makes, in order.
type memoryRecorder struct {
	mu      sync.Mutex
	checks  []store.Check
	steps   []store.Step
	stepsOf []string
}

func (m *memoryRecorder) PutCheck(_ context.Context, c store.Check) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.checks = append(m.checks, c)
	return nil
}

func (m *memoryRecorder) AppendStep(_ context.Context, checkID string, step store.Step) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.steps = append(m.steps, step)
	m.stepsOf = append(m.stepsOf, checkID)
	return nil
}

var npm = store.Submission{Kind: "npm", Ref: "weather-mcp@1.0.0"}

func TestHandlerRecordsTheCheckAsRunningAndItsFirstStep(t *testing.T) {
	rec := &memoryRecorder{}
	result, err := durabletest.NewLocalRunner(Handler(rec)).RunUntilComplete(Input{CheckID: "c1", Submission: npm})
	if err != nil {
		t.Fatal(err)
	}
	out, err := durabletest.ResultAs[Output](result)
	if err != nil {
		t.Fatal(err)
	}
	if out != (Output{CheckID: "c1", Status: store.StatusRunning}) {
		t.Errorf("output = %+v", out)
	}
	if len(rec.checks) != 1 {
		t.Fatalf("recorded %d checks, want 1: %+v", len(rec.checks), rec.checks)
	}
	check := rec.checks[0]
	if check.ID != "c1" || check.Status != store.StatusRunning || check.Submission != npm || check.ExecutionARN == "" {
		t.Errorf("recorded %+v, want c1 running with its submission and execution ARN", check)
	}
	want := []store.Step{{Seq: 1, Name: "start", Summary: "The check started."}}
	if !reflect.DeepEqual(rec.steps, want) || !reflect.DeepEqual(rec.stepsOf, []string{"c1"}) {
		t.Errorf("recorded steps %+v of %v, want %+v of c1", rec.steps, rec.stepsOf, want)
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
		result, err := durabletest.NewLocalRunner(Handler(rec)).RunUntilComplete(tc.in)
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

// The handler is the SDK's handler type, which durable.Start takes.
var _ durable.Handler[Input, Output] = Handler(&memoryRecorder{})
