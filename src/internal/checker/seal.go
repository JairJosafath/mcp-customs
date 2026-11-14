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
// not-sealed finding, which gives at least review.
func (r *run) sealAndRead(ctx durable.Context, in *verdict.Input) error {
	r.sealing = true
	for _, a := range []Action{ActSeal, ActObserve} {
		before := len(r.code)
		err := r.do(ctx, a, nil)
		var stepErr *durable.StepError
		switch {
		case errors.As(err, &stepErr):
			f := findings.Finding{Source: findings.Code, Rule: findings.RuleNotSealed, Evidence: fmt.Sprintf("the %s before the verdict failed, so what the server sent at the end may be unseen", a)}
			r.code = append(r.code, f)
			summary := fmt.Sprintf("The %s before the verdict failed; a person must review.", a)
			if err := r.record(ctx, string(a), outcome{Summary: summary, Findings: []findings.Finding{f}}); err != nil {
				return err
			}
		case err != nil:
			return err
		}
		in.Code = unique(append(in.Code, r.code[before:]...))
	}
	return r.endSandbox(ctx)
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
