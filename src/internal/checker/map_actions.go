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
		// By index: the name is the server's, of any length.
		out = append(out, textPiece{Where: fmt.Sprintf("tool %d", i), Text: t})
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

// probed is one tool's probe: the arguments sent, an excerpt of the
// call's result or error for the judge, and its code findings.
type probed struct {
	Tool      string             `json:"tool"`
	Arguments map[string]any     `json:"arguments"`
	Excerpt   string             `json:"excerpt"`
	Failed    string             `json:"failed,omitempty"`
	Findings  []findings.Finding `json:"findings"`
	Oversized int                `json:"oversized,omitempty"`
}

// probe calls every tool once with the judge's arguments, or stub ones
// where it wrote none, a Map over the tools, each call one step, and scans
// each result: a result is server text too.
func probe(ctx durable.Context, r *run, _ json.RawMessage) (outcome, error) {
	type indexed struct {
		I int  `json:"i"`
		T tool `json:"t"`
	}
	tools := make([]indexed, 0, len(r.listing.Tools))
	var skipped []findings.Finding
	for i, raw := range r.listing.Tools {
		var t tool
		if err := json.Unmarshal(raw, &t); err != nil || t.Name == "" {
			skipped = append(skipped, findings.Finding{
				Source: findings.Code, Rule: findings.RuleUnprobedTool,
				Evidence: fmt.Sprintf("tool %d has no name or isn't a tool's JSON, so it was not probed", i),
			})
			continue
		}
		tools = append(tools, indexed{I: i, T: t})
	}
	res, err := durable.Map(ctx, string(ActProbe), tools, func(mc durable.Context, it indexed, i int) (probed, error) {
		t, args := it.T, stubArguments(it.T)
		if written, ok := r.probeArgs[it.I]; ok {
			args = written
		}
		// Named by index: a tool's name is the server's to choose.
		return durable.Step(mc, fmt.Sprintf("call-%d", i), func(sc durable.StepContext) (probed, error) {
			var answer struct {
				Result json.RawMessage `json:"result"`
				Error  json.RawMessage `json:"error"`
			}
			body := map[string]any{"tool": t.Name, "arguments": args}
			if _, err := callHarness(sc, r.deps.Sandbox, r.vm, http.MethodPost, "/call", body, &answer); err != nil {
				return probed{}, err
			}
			p := probed{Tool: t.Name, Arguments: args, Excerpt: excerpt(jsonStrings(answer.Result)+jsonStrings(answer.Error), maxExcerpt)}
			p.Findings = scanJSON(fmt.Sprintf("the result of tool %d", i), answer.Result)
			if len(answer.Error) > 0 {
				p.Failed = string(answer.Error)
				p.Findings = append(p.Findings, scanJSON(fmt.Sprintf("the error of tool %d", i), answer.Error)...)
			}
			if n := sizeOf(p); n > maxStepResult {
				return probed{Oversized: n}, r.keepOversized(sc, fmt.Sprintf("call-%d", i), answer)
			}
			return p, nil
		}, noRetry)
	})
	if err != nil {
		return outcome{}, err
	}
	found := skipped
	for i, p := range res.Results() {
		if p.Oversized > 0 {
			return outcome{}, r.tooLarge(fmt.Sprintf("call-%d", i), p.Oversized)
		}
		found = append(found, p.Findings...)
	}
	r.probes = res.Results()
	return outcome{
		Summary:  fmt.Sprintf("Probed %d tool(s), %d with the judge's arguments, %d could not be; code flags %d.", len(tools), len(r.probeArgs), len(skipped), len(found)),
		Findings: found,
	}, nil
}
