package checker

import (
	"errors"
	"testing"

	"github.com/aws/aws-durable-execution-sdk-go/durable/durabletest"

	"github.com/JairJosafath/mcp-customs/src/internal/store"
)

func TestAPassWhoseDoneWriteFailsLeavesNoApproval(t *testing.T) {
	w := newWorld(cleanServer())
	w.rec.doneErr = errors.New("throttled")
	result, err := durabletest.NewLocalRunner(Handler(w.deps())).RunUntilComplete(Input{CheckID: "c1", Submission: npm})
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != durabletest.Failed || w.rec.checks[0].Status != store.StatusFailed {
		t.Fatalf("status %s, check %+v; want the check failed", result.Status, w.rec.checks[0])
	}
	if len(w.rec.verdicts) != 0 || len(w.rec.approved) != 0 {
		t.Errorf("HASH# %+v, APPROVED %+v; want no approval of a failed check", w.rec.verdicts, w.rec.approved)
	}
}
