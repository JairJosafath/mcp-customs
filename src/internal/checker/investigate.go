package checker

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"

	"github.com/aws/aws-durable-execution-sdk-go/durable"

	"github.com/JairJosafath/mcp-customs/src/internal/findings"
	"github.com/JairJosafath/mcp-customs/src/internal/verdict"
)

// maxTurns bounds the investigation: running out of turns gives review.
const maxTurns = 8

// maxSeen bounds the hosts and files the judge is shown.
const maxSeen = 50

// writeProbes asks the judge for each tool's probe arguments, in a step,
// and keeps them limited to each tool's input schema. A judge that fails
// leaves every tool to its stub arguments, and the verdict at least
// review.
func (r *run) writeProbes(ctx durable.Context) error {
	r.current = "write_probes"
	req := ProbeRequest{Submission: r.in.Submission, Tools: r.listing.Tools, Canaries: r.judgeCanaries()}
	got, err := durable.Step(ctx, "write-probes", func(sc durable.StepContext) ([]ProbeArgs, error) {
		written, err := r.deps.Judge.WriteProbes(sc, req)
		if err != nil {
			return nil, err
		}
		out := make([]ProbeArgs, 0, len(written))
		for _, p := range written {
			var t tool
			if p.Tool < 0 || p.Tool >= len(r.listing.Tools) || json.Unmarshal(r.listing.Tools[p.Tool], &t) != nil {
				continue
			}
			out = append(out, ProbeArgs{Tool: p.Tool, Arguments: argumentsFor(t, p.Arguments)})
		}
		if sizeOf(out) > maxStepResult {
			return nil, fmt.Errorf("%w: the probes are over %d KB", ErrBadAnswer, maxStepResult>>10)
		}
		return out, nil
	}, noRetry)
	var stepErr *durable.StepError
	if err != nil && !errors.As(err, &stepErr) {
		return err
	}
	if err != nil {
		r.judgeErrs = append(r.judgeErrs, err)
		return r.record(ctx, "write_probes", outcome{Summary: "The judge wrote no probes; every tool is probed with stub arguments."})
	}
	r.probeArgs = map[int]map[string]any{}
	for _, p := range got {
		r.probeArgs[p.Tool] = p.Arguments
	}
	return r.record(ctx, "write_probes", outcome{Summary: fmt.Sprintf("The judge wrote arguments for %d of %d tool(s).", len(r.probeArgs), len(r.listing.Tools))})
}

// judgeCanaries are the run's canaries as the judge is shown them.
func (r *run) judgeCanaries() []Canary {
	out := make([]Canary, 0, len(r.canaries))
	for _, c := range r.canaries {
		out = append(out, Canary{Kind: string(c.Kind), Value: c.Value})
	}
	return out
}

// evidence is what the judge reads, from what the fixed checks found.
func (r *run) evidence() Evidence {
	e := Evidence{
		Submission: r.in.Submission,
		Tools:      r.listing.Tools,
		Resources:  r.listing.Resources,
		Prompts:    r.listing.Prompts,
		Probes:     make([]ProbeEvidence, 0, len(r.probes)),
		Hosts:      r.seen.Hosts,
		Files:      r.seen.Files,
		Code:       unique(r.code),
	}
	for _, p := range r.probes {
		e.Probes = append(e.Probes, ProbeEvidence{Tool: p.Tool, Arguments: p.Arguments, Result: p.Excerpt})
	}
	return e
}

// investigate lets the judge pick one registered action a turn, each
// turn's pick a durable step, until it is done, asks for a person, or
// runs out of turns. Its findings and verdict go into in, for
// verdict.Decide; a judge that fails, or picks what it may not, ends the
// investigation and gives review.
func (r *run) investigate(ctx durable.Context, in *verdict.Input, e Evidence, j Judgement) error {
	for r.turn = 1; r.turn <= maxTurns; r.turn++ {
		r.current = "investigate"
		inv := Investigation{Canaries: r.judgeCanaries(), Evidence: e, Judgement: j, Turns: r.turns, TurnsLeft: maxTurns - r.turn + 1}
		m, err := durable.Step(ctx, fmt.Sprintf("investigate-%d", r.turn), func(sc durable.StepContext) (Move, error) {
			return r.deps.Judge.Next(sc, inv)
		}, noRetry)
		var stepErr *durable.StepError
		if err != nil && !errors.As(err, &stepErr) {
			return err
		}
		if err != nil {
			r.judgeErrs = append(r.judgeErrs, err)
			return r.record(ctx, "investigate", outcome{Summary: fmt.Sprintf("Turn %d: the judge failed; a person must review.", r.turn)})
		}
		in.Model = append(in.Model, m.Findings...)
		in.ModelVerdict = stricterOf(in.ModelVerdict, m.Verdict)
		summary := fmt.Sprintf("Turn %d of %d: the judge picked %s.", r.turn, maxTurns, m.Action)
		action, allowed := moveActions[m.Action]
		switch {
		case !allowed:
			r.judgeErrs = append(r.judgeErrs, fmt.Errorf("%w: the action %q", ErrBadAnswer, m.Action))
			return r.record(ctx, "investigate", outcome{Summary: fmt.Sprintf("Turn %d: the judge picked an action it may not; a person must review.", r.turn)})
		case m.Action == MoveDone:
			return r.record(ctx, "investigate", outcome{Summary: summary + " The investigation is over."})
		case action == ActAskHuman:
			in.Model = append(in.Model, findings.Finding{Source: findings.Model, Rule: RuleAskedForHuman, Evidence: excerpt(m.Reason, maxEvidenceLength)})
			return r.record(ctx, "investigate", outcome{Summary: summary + " A person will decide."})
		}
		if err := r.record(ctx, "investigate", outcome{Summary: summary}); err != nil {
			return err
		}
		r.outcome = ""
		err = r.do(ctx, action, m.Arguments)
		if errors.Is(err, ErrBadArguments) {
			r.judgeErrs = append(r.judgeErrs, err)
			return r.record(ctx, "investigate", outcome{Summary: fmt.Sprintf("Turn %d: the judge's arguments were not what %s takes; a person must review.", r.turn, action)})
		}
		if err != nil {
			return err
		}
		r.turns = append(r.turns, Turn{Move: m, Outcome: r.outcome})
	}
	in.OutOfTurns = true
	return r.record(ctx, "investigate", outcome{Summary: fmt.Sprintf("The investigation ran out of its %d turns; a person must review.", maxTurns)})
}

var strictness = map[verdict.Verdict]int{verdict.Pass: 1, verdict.Review: 2, verdict.Block: 3}

// stricterOf is the stricter of two verdicts the judge gave; an empty one
// is none.
func stricterOf(a, b verdict.Verdict) verdict.Verdict {
	if strictness[b] > strictness[a] {
		return b
	}
	return a
}

// seen are the hosts the server was seen reaching and the files it wrote,
// in the order first seen, at most maxSeen of each.
type seen struct {
	Hosts []string `json:"hosts"`
	Files []string `json:"files"`
}

func seenIn(obs []findings.Observation) seen {
	s := seen{Hosts: []string{}, Files: []string{}}
	for _, o := range obs {
		var d struct {
			Host string `json:"host"`
			Name string `json:"name"`
			Path string `json:"path"`
		}
		if json.Unmarshal(o.Detail, &d) != nil {
			continue
		}
		switch o.Kind {
		case findings.ObservedDNS, findings.ObservedConnect, findings.ObservedHTTP:
			host := d.Host
			if host == "" {
				host = d.Name
			}
			s.Hosts = addSeen(s.Hosts, host)
		case findings.ObservedFile:
			s.Files = addSeen(s.Files, d.Path)
		}
	}
	return s
}

func addSeen(list []string, v string) []string {
	if v == "" || len(v) > 512 || len(list) >= maxSeen || slices.Contains(list, v) {
		return list
	}
	return append(list, v)
}
