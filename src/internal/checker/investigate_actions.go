package checker

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"path"
	"slices"
	"strings"
	"time"

	"github.com/aws/aws-durable-execution-sdk-go/durable"

	"github.com/JairJosafath/mcp-customs/src/internal/findings"
)

// maxExcerpt bounds the server text an action keeps for the judge.
const maxExcerpt = 4 << 10

// maxClock bounds how far the investigation may move the sandbox's clock.
const maxClock = 365 * 24 * time.Hour

// harnessRefused is the outcome of an investigation action the harness
// answered with an error: the judge is told, and the check goes on.
const harnessRefused = "The harness could not do this."

// brought is what an investigation action brought back: an excerpt of the
// server's text for the judge, and the code findings of all of it.
type brought struct {
	Excerpt  string             `json:"excerpt"`
	Refused  bool               `json:"refused,omitempty"`
	Findings []findings.Finding `json:"findings"`
	// Oversized is the answer's size when it was too large to keep.
	Oversized int `json:"oversized,omitempty"`
}

// decodeArgs decodes an action's arguments strictly into v.
func decodeArgs(args json.RawMessage, v any) error {
	if err := strictDecode(args, v); err != nil {
		return fmt.Errorf("%w: %w", ErrBadArguments, err)
	}
	return nil
}

// harnessStep makes one Harness API call for an investigation action, in a
// step named after the action and the turn. The answer's text is scanned
// whole and kept as an excerpt; what the call was seen doing becomes code
// findings. A harness error is the judge's to hear, not the check's end.
func (r *run) harnessStep(ctx durable.Context, a Action, route string, body any, text func(json.RawMessage) string) (brought, error) {
	name := fmt.Sprintf("%s-%d", a, r.turn)
	got, err := durable.Step(ctx, name, func(sc durable.StepContext) (brought, error) {
		var answer json.RawMessage
		obs, err := callHarness(sc, r.deps.Sandbox, r.vm, http.MethodPost, route, body, &answer)
		if errors.Is(err, ErrHarness) {
			return brought{Refused: true, Excerpt: harnessRefused, Findings: findings.FromObservations(obs, r.canaries)}, nil
		}
		if err != nil {
			return brought{}, err
		}
		s := text(answer)
		found := findings.ScanText(s).Findings
		found = append(found, findings.FromObservations(obs, r.canaries)...)
		for i := range found {
			found[i].Evidence = fmt.Sprintf("turn %d (%s): %s", r.turn, a, found[i].Evidence)
		}
		got := brought{Excerpt: excerpt(s, maxExcerpt), Findings: found}
		if n := sizeOf(got); n > maxStepResult {
			return brought{Oversized: n}, r.keepOversized(sc, name, answer)
		}
		return got, nil
	}, noRetry)
	if err != nil {
		return brought{}, err
	}
	if got.Oversized > 0 {
		return brought{}, r.tooLarge(name, got.Oversized)
	}
	r.outcome = got.Excerpt
	return got, nil
}

// excerpt is the first n bytes of s, cut at a character.
func excerpt(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return strings.ToValidUTF8(s[:n], "")
}

func (l brought) outcome(did string) outcome {
	if l.Refused {
		return outcome{Summary: fmt.Sprintf("%s: the harness refused.", did), Findings: l.Findings}
	}
	return outcome{Summary: fmt.Sprintf("%s; code flags %d.", did, len(l.Findings)), Findings: l.Findings}
}

// field is the strings of one field of a JSON answer, as a model reads them.
func field(name string) func(json.RawMessage) string {
	return func(raw json.RawMessage) string {
		var m map[string]json.RawMessage
		if json.Unmarshal(raw, &m) != nil {
			return ""
		}
		return jsonStrings(m[name])
	}
}

type callArgs struct {
	Tool      string         `json:"tool"`
	Arguments map[string]any `json:"arguments"`
}

// call probes one tool again with the judge's arguments, limited to its
// input schema.
func call(ctx durable.Context, r *run, args json.RawMessage) (outcome, error) {
	var a callArgs
	if err := decodeArgs(args, &a); err != nil {
		return outcome{}, err
	}
	i := slices.IndexFunc(r.listing.Tools, func(raw json.RawMessage) bool {
		var t tool
		return json.Unmarshal(raw, &t) == nil && t.Name == a.Tool && a.Tool != ""
	})
	if i < 0 {
		return outcome{}, fmt.Errorf("%w: no listed tool has that name", ErrBadArguments)
	}
	var t tool
	if err := json.Unmarshal(r.listing.Tools[i], &t); err != nil {
		return outcome{}, fmt.Errorf("%w: %w", ErrBadArguments, err)
	}
	body := map[string]any{"tool": t.Name, "arguments": argumentsFor(t, a.Arguments)}
	got, err := r.harnessStep(ctx, ActCall, "/call", body, func(raw json.RawMessage) string {
		return field("result")(raw) + field("error")(raw)
	})
	if err != nil {
		return outcome{}, err
	}
	return got.outcome(fmt.Sprintf("Called tool %d again with the judge's arguments", i)), nil
}

type pathArgs struct {
	Path string `json:"path"`
}

// readSource reads one file of the installed package, by a path relative
// to it that the harness named.
func readSource(ctx durable.Context, r *run, args json.RawMessage) (outcome, error) {
	var a pathArgs
	if err := decodeArgs(args, &a); err != nil {
		return outcome{}, err
	}
	if a.Path == "" || len(a.Path) > 256 || path.IsAbs(a.Path) || path.Clean(a.Path) != a.Path || strings.HasPrefix(a.Path, "..") {
		return outcome{}, fmt.Errorf("%w: a source path is relative to the package, clean, and at most 256 characters", ErrBadArguments)
	}
	got, err := r.harnessStep(ctx, ActReadSource, "/source", map[string]any{"path": a.Path}, field("content"))
	if err != nil {
		return outcome{}, err
	}
	return got.outcome("Read a source file of the package"), nil
}

// inspectDownload has the harness describe a file the server wrote.
func inspectDownload(ctx durable.Context, r *run, args json.RawMessage) (outcome, error) {
	var a pathArgs
	if err := decodeArgs(args, &a); err != nil {
		return outcome{}, err
	}
	if !path.IsAbs(a.Path) || len(a.Path) > 512 || path.Clean(a.Path) != a.Path {
		return outcome{}, fmt.Errorf("%w: a download's path is absolute, clean, and at most 512 characters", ErrBadArguments)
	}
	got, err := r.harnessStep(ctx, ActInspectDownload, "/download", map[string]any{"path": a.Path}, jsonStrings)
	if err != nil {
		return outcome{}, err
	}
	return got.outcome("Inspected a file the server wrote"), nil
}

type clockArgs struct {
	Offset string `json:"offset"`
}

// clock moves the sandbox's clock forward, for a trigger that waits.
func clock(ctx durable.Context, r *run, args json.RawMessage) (outcome, error) {
	var a clockArgs
	if err := decodeArgs(args, &a); err != nil {
		return outcome{}, err
	}
	d, err := time.ParseDuration(a.Offset)
	if err != nil || d < time.Minute || d > maxClock {
		return outcome{}, fmt.Errorf("%w: a clock offset is a duration of a minute to %s", ErrBadArguments, maxClock)
	}
	got, err := r.harnessStep(ctx, ActClock, "/clock", map[string]any{"offset": d.String()}, jsonStrings)
	if err != nil {
		return outcome{}, err
	}
	return got.outcome(fmt.Sprintf("Moved the sandbox's clock %s forward", d)), nil
}

type allowArgs struct {
	Hosts []string `json:"hosts"`
}

// allow sets the sandbox's egress allowlist to the hosts the judge expects
// for the server's purpose. It never allows the stack's own API host, or a
// name that resolves to it: that refusal is a code finding, and ends the
// investigation.
func allow(ctx durable.Context, r *run, args json.RawMessage) (outcome, error) {
	var a allowArgs
	if err := decodeArgs(args, &a); err != nil {
		return outcome{}, err
	}
	if a.Hosts == nil {
		a.Hosts = []string{}
	}
	if len(a.Hosts) > maxHosts || slices.ContainsFunc(a.Hosts, func(h string) bool { return !allowedHost(h) }) {
		return outcome{}, fmt.Errorf("%w: at most %d host names", ErrBadArguments, maxHosts)
	}
	refusal, err := r.ownAPIRefusal(ctx, a.Hosts)
	if err != nil {
		return outcome{}, err
	}
	if refusal != "" {
		return r.refuseOwnAPI(refusal), nil
	}
	got, err := r.harnessStep(ctx, ActAllow, "/allow", map[string]any{"hosts": a.Hosts}, func(json.RawMessage) string { return "" })
	if err != nil {
		return outcome{}, err
	}
	return got.outcome(fmt.Sprintf("Allowed the %d host(s) the judge expects for the server's purpose", len(a.Hosts))), nil
}
