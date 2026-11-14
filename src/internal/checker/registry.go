package checker

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/aws/aws-durable-execution-sdk-go/durable"

	"github.com/JairJosafath/mcp-customs/src/internal/findings"
	"github.com/JairJosafath/mcp-customs/src/internal/store"
)

// Action names one registered thing a check can do. The fixed checks run
// them in an order code decides; the judge's investigation picks call,
// read_source, inspect_download, clock or ask_human, one a turn, by name.
type Action string

// The registered actions.
const (
	ActResolve  Action = "resolve"
	ActLookup   Action = "lookup"
	ActInstall  Action = "install"
	ActList     Action = "list"
	ActScan     Action = "scan"
	ActProbe    Action = "probe"
	ActObserve  Action = "observe"
	ActAskHuman Action = "ask_human"
	ActWait     Action = "wait"
	// ActSeal ends the sandbox's egress before the last read of its
	// observations.
	ActSeal Action = "seal"
	// The investigation's: one tool called again, a source file read, a
	// download inspected, the clock moved; and the judge's allowlist set.
	ActCall            Action = "call"
	ActReadSource      Action = "read_source"
	ActInspectDownload Action = "inspect_download"
	ActClock           Action = "clock"
	ActAllow           Action = "allow"
)

// Operation is the durable operation an action runs as.
type Operation string

// The durable operations of the SDK an action can be.
const (
	OpStep     Operation = "Step"
	OpMap      Operation = "Map"
	OpCallback Operation = "WaitForCallback"
	OpWait     Operation = "Wait"
)

// outcome is what an action did, for its STEP# item: a one-line summary
// and the code findings it made.
type outcome struct {
	Summary  string
	Findings []findings.Finding
}

// entry is one action in the registry: the durable operation it is, and
// what runs it. run makes exactly one durable operation of kind op, so a
// replay returns its recorded result instead of running it again.
type entry struct {
	op  Operation
	run func(ctx durable.Context, r *run, args json.RawMessage) (outcome, error)
}

// registry maps each action to its one durable operation.
var registry = map[Action]entry{
	ActResolve:  {OpStep, resolve},
	ActLookup:   {OpStep, lookup},
	ActInstall:  {OpStep, install},
	ActList:     {OpStep, list},
	ActScan:     {OpMap, scan},
	ActProbe:    {OpMap, probe},
	ActObserve:  {OpStep, observe},
	ActAskHuman: {OpCallback, askHuman},
	ActWait:     {OpWait, wait},
	ActSeal:     {OpStep, seal},

	ActCall:            {OpStep, call},
	ActReadSource:      {OpStep, readSource},
	ActInspectDownload: {OpStep, inspectDownload},
	ActClock:           {OpStep, clock},
	ActAllow:           {OpStep, allow},
}

// OperationOf answers the durable operation action runs as, and false for
// an action that isn't registered.
func OperationOf(a Action) (Operation, bool) {
	e, ok := registry[a]
	return e.op, ok
}

// ErrUnknownAction says an action isn't in the registry.
var ErrUnknownAction = errors.New("the action is not registered")

// ErrBadArguments says an action's arguments aren't what it takes.
var ErrBadArguments = errors.New("the action's arguments are not what it takes")

// do runs action a with args, then records its STEP# item in a step of its
// own: a replay finds both recorded and runs neither again.
func (r *run) do(ctx durable.Context, a Action, args json.RawMessage) error {
	e, ok := registry[a]
	if !ok {
		return fmt.Errorf("%q: %w", a, ErrUnknownAction)
	}
	r.current = string(a)
	out, err := e.run(ctx, r, args)
	if err != nil {
		return fmt.Errorf("%s: %w", a, err)
	}
	r.code = append(r.code, out.Findings...)
	return r.record(ctx, string(a), out)
}

// record writes the check's next STEP# item, in a durable step named after
// its number.
func (r *run) record(ctx durable.Context, name string, out outcome) error {
	r.seq++
	step := boundStep(r.in.CheckID, store.Step{Seq: r.seq, Name: name, Summary: out.Summary}, out.Findings)
	if _, err := durable.Step(ctx, fmt.Sprintf("step-%04d", r.seq), func(sc durable.StepContext) (bool, error) {
		return true, r.deps.Store.AppendStep(sc, r.in.CheckID, step)
	}); err != nil {
		return fmt.Errorf("record step %d (%s) of check %s: %w", r.seq, name, r.in.CheckID, err)
	}
	return nil
}

func storeFindings(in []findings.Finding) []store.Finding {
	out := make([]store.Finding, 0, len(in))
	for _, f := range in {
		out = append(out, store.Finding{Source: string(f.Source), Rule: f.Rule, Evidence: f.Evidence})
	}
	return out
}
