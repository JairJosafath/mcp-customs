package checker

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/aws/aws-durable-execution-sdk-go/durable"

	"github.com/JairJosafath/mcp-customs/src/internal/findings"
)

// textPiece is one piece of server text to scan: a tool whole, a resource,
// a prompt, or the server's initialize result, which carries its
// instructions.
type textPiece struct {
	Where string          `json:"where"`
	Text  json.RawMessage `json:"text"`
}

// pieces are all the server text the listing holds, one piece a tool,
// resource and prompt.
func (l listing) pieces() []textPiece {
	var out []textPiece
	for i, t := range l.Tools {
		var named tool
		_ = json.Unmarshal(t, &named)
		out = append(out, textPiece{Where: fmt.Sprintf("tool %d (%q)", i, named.Name), Text: t})
	}
	for i, res := range l.Resources {
		out = append(out, textPiece{Where: fmt.Sprintf("resource %d", i), Text: res})
	}
	for i, p := range l.Prompts {
		out = append(out, textPiece{Where: fmt.Sprintf("prompt %d", i), Text: p})
	}
	if len(l.Initialize) > 0 {
		out = append(out, textPiece{Where: "initialize", Text: l.Initialize})
	}
	return out
}

// scan scans all the server's text with findings.ScanText, a Map over its
// tools, resources and prompts. Scanning is pure code: each item's result
// is recorded as the Map's, so a replay doesn't scan again.
func scan(ctx durable.Context, r *run, _ json.RawMessage) (outcome, error) {
	pieces := r.listing.pieces()
	res, err := durable.Map(ctx, string(ActScan), pieces, func(_ durable.Context, p textPiece, _ int) ([]findings.Finding, error) {
		return scanJSON(p.Where, p.Text), nil
	})
	if err != nil {
		return outcome{}, err
	}
	var found []findings.Finding
	for _, f := range res.Results() {
		found = append(found, f...)
	}
	return outcome{Summary: fmt.Sprintf("Scanned %d piece(s) of server text; code flags %d.", len(pieces), len(found)), Findings: found}, nil
}

// probed is one tool's probe: the call's result or error, scanned.
type probed struct {
	Tool     string             `json:"tool"`
	Failed   string             `json:"failed,omitempty"`
	Findings []findings.Finding `json:"findings"`
}

// probe calls every tool once with stub arguments, a Map over the tools,
// each call one step, and scans each result: a result is server text too.
func probe(ctx durable.Context, r *run, _ json.RawMessage) (outcome, error) {
	tools := make([]tool, 0, len(r.listing.Tools))
	for _, raw := range r.listing.Tools {
		var t tool
		if err := json.Unmarshal(raw, &t); err != nil || t.Name == "" {
			continue
		}
		tools = append(tools, t)
	}
	res, err := durable.Map(ctx, string(ActProbe), tools, func(mc durable.Context, t tool, _ int) (probed, error) {
		return durable.Step(mc, "call "+t.Name, func(sc durable.StepContext) (probed, error) {
			var answer struct {
				Result json.RawMessage `json:"result"`
				Error  json.RawMessage `json:"error"`
			}
			body := map[string]any{"tool": t.Name, "arguments": stubArguments(t)}
			if _, err := callHarness(sc, r.deps.Sandbox, r.vm, http.MethodPost, "/call", body, &answer); err != nil {
				return probed{}, err
			}
			p := probed{Tool: t.Name, Findings: scanJSON(fmt.Sprintf("the result of %q", t.Name), answer.Result)}
			if len(answer.Error) > 0 {
				p.Failed = string(answer.Error)
				p.Findings = append(p.Findings, scanJSON(fmt.Sprintf("the error of %q", t.Name), answer.Error)...)
			}
			return p, nil
		}, noRetry)
	})
	if err != nil {
		return outcome{}, err
	}
	var found []findings.Finding
	for _, p := range res.Results() {
		found = append(found, p.Findings...)
	}
	r.probes = res.Results()
	return outcome{Summary: fmt.Sprintf("Probed %d tool(s) with stub arguments; code flags %d in their results.", len(tools), len(found)), Findings: found}, nil
}
