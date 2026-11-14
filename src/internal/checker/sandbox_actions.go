package checker

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/aws/aws-durable-execution-sdk-go/durable"

	"github.com/JairJosafath/mcp-customs/src/internal/canary"
	"github.com/JairJosafath/mcp-customs/src/internal/checker/sandbox"
	"github.com/JairJosafath/mcp-customs/src/internal/findings"
	"github.com/JairJosafath/mcp-customs/src/internal/store"
)

// noRetry is for steps that change the sandbox: a second attempt would find
// the server installed or started already, or call a tool twice.
var noRetry = durable.WithRetry(durable.NoRetry())

// maxLogTail bounds how much of the install log a check keeps.
const maxLogTail = 2048

// resolved is what resolve found: the sandbox it launched (without its
// token), the canaries planted in it, the hash of the whole resolved
// dependency set, and the code findings of what the install was seen
// doing. The observations themselves are the server's, of any number, so
// they are never kept in the step: observe keeps them all in the bucket.
type resolved struct {
	VM       sandbox.VM         `json:"vm"`
	Canaries canary.Set         `json:"canaries"`
	Hash     string             `json:"hash"`
	LogTail  string             `json:"logTail"`
	Findings []findings.Finding `json:"findings"`
	// Oversized is the answer's size when it was too large to keep.
	Oversized int `json:"oversized,omitempty"`
}

// rawAnswer is an oversized answer as the bucket keeps it: the
// observations behind it and what code made of them.
type rawAnswer struct {
	Initialize   json.RawMessage        `json:"initialize,omitempty"`
	Observations []findings.Observation `json:"observations"`
	Findings     []findings.Finding     `json:"findings"`
}

type installAnswer struct {
	Log    string `json:"log"`
	SHA256 string `json:"sha256"`
}

// resolve launches the check's sandbox with fresh canaries and a fresh run
// token, and has the harness resolve and install the submission there:
// the Checker never reaches a registry or a remote server itself. The
// harness hashes the whole resolved dependency set.
func resolve(ctx durable.Context, r *run, _ json.RawMessage) (outcome, error) {
	res, err := durable.Step(ctx, string(ActResolve), func(sc durable.StepContext) (resolved, error) {
		token := r.deps.Token(r.in.CheckID)
		set := r.deps.Canaries()
		vm, err := r.deps.Sandbox.Launch(sc, sandbox.Launch{IdempotencyKey: r.in.CheckID, Token: token, Canaries: sandboxCanaries(set)})
		if err != nil {
			return resolved{}, fmt.Errorf("launch the sandbox: %w", err)
		}
		// First, so a failure can end the sandbox even if this step never
		// finishes.
		if err := r.deps.Store.UpdateCheck(sc, r.in.CheckID, store.CheckUpdate{SandboxID: vm.ID}); err != nil {
			return resolved{}, err
		}
		// The checkpoint keeps no token: the execution's history outlives
		// the sandbox. It is derived again below, on every replay.
		res := resolved{VM: vm, Canaries: set}
		res.VM.Token = ""
		var answer installAnswer
		body := map[string]any{"kind": r.in.Submission.Kind, "ref": r.in.Submission.Ref, "canaries": set, "allowHosts": []string{}}
		obs, err := callHarness(sc, r.deps.Sandbox, vm, http.MethodPost, "/install", body, &answer)
		if err != nil {
			// Nothing after a failed step knows this sandbox: end it here.
			if endErr := r.deps.Sandbox.Terminate(sc, vm); endErr != nil {
				return res, fmt.Errorf("%w; and end the sandbox: %w", err, endErr)
			}
			return res, err
		}
		res.Hash, res.LogTail = answer.SHA256, tail(answer.Log, maxLogTail)
		res.Findings = findings.FromObservations(obs, set)
		if n := sizeOf(res); n > maxStepResult {
			// The sandbox is kept, so the failure can end it.
			return resolved{VM: res.VM, Oversized: n}, r.keepOversized(sc, string(ActResolve), rawAnswer{Observations: obs, Findings: res.Findings})
		}
		return res, nil
	}, noRetry)
	if err != nil {
		return outcome{}, err
	}
	r.vm, r.canaries, r.resolved = res.VM, res.Canaries, res
	if res.Oversized > 0 {
		r.vm.Token = r.deps.Token(r.in.CheckID)
		return outcome{}, r.tooLarge(string(ActResolve), res.Oversized)
	}
	r.vm.Token = r.deps.Token(r.in.CheckID)
	return outcome{Summary: fmt.Sprintf("Resolved %s %s in the sandbox; its dependency set hashes to %s.", r.in.Submission.Kind, r.in.Submission.Ref, res.Hash)}, nil
}

// looked is what lookup found: the approved verdict of the hash, if any.
type looked struct {
	Found   bool          `json:"found"`
	Verdict store.Verdict `json:"verdict"`
}

// lookup reads the approved verdict of the resolved dependency set's hash.
func lookup(ctx durable.Context, r *run, _ json.RawMessage) (outcome, error) {
	got, err := durable.Step(ctx, string(ActLookup), func(sc durable.StepContext) (looked, error) {
		v, found, err := r.deps.Store.GetVerdict(sc, r.resolved.Hash)
		return looked{Found: found, Verdict: v}, err
	})
	if err != nil {
		return outcome{}, err
	}
	if !got.Found {
		return outcome{Summary: "No earlier check approved this dependency set."}, nil
	}
	r.approved = &got.Verdict
	return outcome{Summary: fmt.Sprintf("Check %s approved this dependency set before.", got.Verdict.CheckID)}, nil
}

// started is what starting the server brought back.
type started struct {
	Initialize   json.RawMessage        `json:"initialize"`
	Observations []findings.Observation `json:"observations"`
}

// start starts the installed server, once.
func (r *run) start(sc durable.StepContext) (started, error) {
	var s started
	obs, err := callHarness(sc, r.deps.Sandbox, r.vm, http.MethodPost, "/start", map[string]any{}, &s)
	s.Observations = obs
	return s, err
}

// installed is what install recorded: the server's initialize result, if
// install started it, and the code findings of everything the install and
// the start did.
type installed struct {
	Started    bool               `json:"started"`
	Initialize json.RawMessage    `json:"initialize,omitempty"`
	Findings   []findings.Finding `json:"findings"`
	// Oversized is the answer's size when it was too large to keep.
	Oversized int `json:"oversized,omitempty"`
}

// install closes the recorded install phase: it starts the installed
// server, unless list started it already, and turns what the install and
// the start were seen doing into code findings.
func install(ctx durable.Context, r *run, _ json.RawMessage) (outcome, error) {
	got, err := durable.Step(ctx, string(ActInstall), func(sc durable.StepContext) (installed, error) {
		out := installed{Started: r.listing.Started}
		var s started
		if !out.Started {
			var err error
			if s, err = r.start(sc); err != nil {
				return out, err
			}
			out.Started, out.Initialize = true, s.Initialize
		}
		out.Findings = unique(append(append([]findings.Finding{}, r.resolved.Findings...), findings.FromObservations(s.Observations, r.canaries)...))
		if n := sizeOf(out); n > maxStepResult {
			return installed{Oversized: n}, r.keepOversized(sc, string(ActInstall), rawAnswer{Initialize: s.Initialize, Observations: s.Observations, Findings: out.Findings})
		}
		return out, nil
	}, noRetry)
	if err != nil {
		return outcome{}, err
	}
	if got.Oversized > 0 {
		return outcome{}, r.tooLarge(string(ActInstall), got.Oversized)
	}
	if got.Initialize != nil {
		r.listing.Initialize = got.Initialize
	}
	r.listing.Started = true
	return outcome{
		Summary:  fmt.Sprintf("Installed and started the server; the install was seen doing %d thing(s) code flags.", len(got.Findings)),
		Findings: got.Findings,
	}, nil
}

// listing is what the server lists: its tools with their whole schemas,
// its resources and prompts, its initialize result, and the hash of its
// tool list.
type listing struct {
	Started    bool              `json:"started"`
	Initialize json.RawMessage   `json:"initialize"`
	Tools      []json.RawMessage `json:"tools"`
	Resources  []json.RawMessage `json:"resources"`
	Prompts    []json.RawMessage `json:"prompts"`
	ToolHash   string            `json:"toolHash"`
	// Oversized is the listing's size when it was too large to keep.
	Oversized int `json:"oversized,omitempty"`
}

// list starts the server if nothing started it yet, lists its tools,
// resources and prompts, and hashes the tool list.
func list(ctx durable.Context, r *run, _ json.RawMessage) (outcome, error) {
	got, err := durable.Step(ctx, string(ActList), func(sc durable.StepContext) (listing, error) {
		l := r.listing
		if !l.Started {
			s, err := r.start(sc)
			if err != nil {
				return l, err
			}
			l.Started, l.Initialize = true, s.Initialize
		}
		if _, err := callHarness(sc, r.deps.Sandbox, r.vm, http.MethodPost, "/list", map[string]any{}, &l); err != nil {
			return l, err
		}
		hash, err := toolListHash(l.Tools)
		if err != nil {
			return l, err
		}
		l.ToolHash = hash
		if n := sizeOf(l); n > maxStepResult {
			return listing{Oversized: n}, r.keepOversized(sc, "list", l)
		}
		return l, nil
	}, noRetry)
	if err != nil {
		return outcome{}, err
	}
	if got.Oversized > 0 {
		return outcome{}, r.tooLarge("list", got.Oversized)
	}
	r.listing, r.listed = got, true
	return outcome{Summary: fmt.Sprintf("Listed %d tool(s), %d resource(s) and %d prompt(s); the tool list hashes to %s.",
		len(got.Tools), len(got.Resources), len(got.Prompts), got.ToolHash)}, nil
}

// observed is what observe found: how many observations the run made, and
// their code findings. The observations themselves go to the bucket.
type observed struct {
	Count     int                `json:"count"`
	Seen      seen               `json:"seen"`
	Findings  []findings.Finding `json:"findings"`
	Oversized int                `json:"oversized,omitempty"`
}

// observe reads every observation of the run, keeps them in the bucket as
// observations/<check-id>.json, and makes their code findings.
func observe(ctx durable.Context, r *run, _ json.RawMessage) (outcome, error) {
	got, err := durable.Step(ctx, string(ActObserve), func(sc durable.StepContext) (observed, error) {
		var all struct {
			Observations []findings.Observation `json:"observations"`
		}
		if _, err := callHarness(sc, r.deps.Sandbox, r.vm, http.MethodGet, "/observations", nil, &all); err != nil {
			return observed{}, err
		}
		raw, err := json.Marshal(all.Observations)
		if err != nil {
			return observed{}, fmt.Errorf("encode the observations: %w", err)
		}
		if err := r.deps.Reports.PutObservations(sc, r.in.CheckID, raw); err != nil {
			return observed{}, err
		}
		got := observed{Count: len(all.Observations), Seen: seenIn(all.Observations), Findings: findings.FromObservations(all.Observations, r.canaries)}
		if n := sizeOf(got); n > maxStepResult {
			return observed{Oversized: n}, r.keepOversized(sc, "observe", got)
		}
		return got, nil
	})
	if err != nil {
		return outcome{}, err
	}
	if got.Oversized > 0 {
		return outcome{}, r.tooLarge("observe", got.Oversized)
	}
	r.seen = got.Seen
	return outcome{
		Summary:  fmt.Sprintf("Read %d observation(s) of the run; code flags %d.", got.Count, len(got.Findings)),
		Findings: got.Findings,
	}, nil
}

func sandboxCanaries(set canary.Set) []sandbox.Canary {
	out := make([]sandbox.Canary, 0, len(set))
	for _, c := range set {
		out = append(out, sandbox.Canary{Kind: string(c.Kind), Value: c.Value})
	}
	return out
}

// tail is the last n bytes of s.
func tail(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return strings.ToValidUTF8(s[len(s)-n:], "")
}
