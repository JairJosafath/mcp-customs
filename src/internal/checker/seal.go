package checker

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/aws/aws-durable-execution-sdk-go/durable"

	"github.com/JairJosafath/mcp-customs/src/internal/findings"
	"github.com/JairJosafath/mcp-customs/src/internal/verdict"
)

// sealAndRead seals the sandbox's egress, reads its observations a last
// time, and only then ends the sandbox, so nothing the server sends after
// the read leaves it unseen. What the read finds joins in's code findings,
// which the verdict is decided from. A seal or a read that fails adds a
// not-sealed finding; one that works but whose STEP# item can't be
// written adds a step-not-recorded finding. Either gives at least review.
func (r *run) sealAndRead(ctx durable.Context, in *verdict.Input) error {
	r.sealing = true
	for _, a := range []Action{ActSeal, ActObserve} {
		before := len(r.code)
		if err := r.sealStep(ctx, a); err != nil {
			return err
		}
		in.Code = unique(append(in.Code, r.code[before:]...))
	}
	return r.endSandbox(ctx)
}

// sealStep runs a, the seal or the last read, and records its STEP# item,
// turning a failure of either into the code finding that says which.
func (r *run) sealStep(ctx durable.Context, a Action) error {
	var stepErr *durable.StepError
	out, err := r.act(ctx, a, nil)
	switch {
	case errors.As(err, &stepErr):
		f := findings.Finding{Source: findings.Code, Rule: findings.RuleNotSealed, Evidence: fmt.Sprintf("the %s before the verdict failed, so what the server sent at the end may be unseen", a)}
		r.code = append(r.code, f)
		summary := fmt.Sprintf("The %s before the verdict failed; a person must review.", a)
		return r.record(ctx, string(a), outcome{Summary: summary, Findings: []findings.Finding{f}})
	case err != nil:
		return err
	}
	err = r.record(ctx, string(a), out)
	if errors.As(err, &stepErr) {
		// The store just failed a write, so the finding goes to the verdict
		// step rather than a step of its own.
		r.code = append(r.code, findings.Finding{Source: findings.Code, Rule: findings.RuleStepNotRecorded, Evidence: fmt.Sprintf("the %s before the verdict worked, but its step could not be recorded", a)})
		return nil
	}
	return err
}

// seal ends the sandbox's egress for good: the harness empties its
// allowlist and refuses every new connection. Sealing again does no harm,
// so a retry may.
func seal(ctx durable.Context, r *run, _ json.RawMessage) (outcome, error) {
	if _, err := durable.Step(ctx, string(ActSeal), func(sc durable.StepContext) (bool, error) {
		_, err := callHarness(sc, r.deps.Sandbox, r.vm, http.MethodPost, "/seal", map[string]any{}, nil)
		return err == nil, err
	}); err != nil {
		return outcome{}, err
	}
	return outcome{Summary: "Sealed the sandbox's egress: nothing the server sends from here leaves it."}, nil
}
