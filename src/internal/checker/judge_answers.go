package checker

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"

	"github.com/JairJosafath/mcp-customs/src/internal/findings"
	"github.com/JairJosafath/mcp-customs/src/internal/verdict"
)

// The rules of the judge's findings. Each is a model finding, so it gives
// at least review and clears nothing.
const (
	RulePurposeMismatch = "purpose-mismatch"
	RuleInstructsModel  = "server-instructs-model"
	RuleJudgeConcern    = "judge-concern"
	RuleAskedForHuman   = "judge-asked-for-a-person"
)

// The limits on what the judge may answer: past them, the answer is not
// what the schema allows, and is refused.
const (
	maxModelFindings  = 20
	maxEvidenceLength = 1000
	maxHosts          = 20
	maxProbeArgsBytes = 8 << 10
)

// The tools the judge answers through, one a call, each with its JSON
// Schema. The model's answer is the tool's input; code decodes it with
// the same limits, and refuses anything else.
const (
	ToolProbes    = "write_probes"
	ToolJudgement = "judge_server"
	ToolMove      = "next_move"
)

// ErrBadAnswer says the judge answered something its schema doesn't
// allow; the check treats it as the judge failing, which gives review.
var ErrBadAnswer = errors.New("the judge's answer is not what its schema allows")

// ProbesSchema is the JSON Schema of the write_probes tool's input.
const ProbesSchema = `{
  "type": "object",
  "additionalProperties": false,
  "required": ["probes"],
  "properties": {
    "probes": {
      "type": "array",
      "description": "One entry per tool to probe.",
      "items": {
        "type": "object",
        "additionalProperties": false,
        "required": ["tool", "arguments"],
        "properties": {
          "tool": {"type": "integer", "minimum": 0, "description": "The tool's index in the evidence."},
          "arguments": {"type": "object", "description": "Realistic arguments that satisfy the tool's inputSchema."}
        }
      }
    }
  }
}`

// findingSchema is one model finding in a schema.
const findingSchema = `{
  "type": "object",
  "additionalProperties": false,
  "required": ["rule", "evidence"],
  "properties": {
    "rule": {"enum": ["purpose-mismatch", "server-instructs-model", "judge-concern"]},
    "evidence": {"type": "string", "maxLength": 1000, "description": "What in the evidence shows it, quoted or named."}
  }
}`

// JudgementSchema is the JSON Schema of the judge_server tool's input.
const JudgementSchema = `{
  "type": "object",
  "additionalProperties": false,
  "required": ["verdict", "fitsPurpose", "instructsModel", "findings", "expectedHosts"],
  "properties": {
    "verdict": {"enum": ["pass", "review", "block"]},
    "fitsPurpose": {"type": "boolean", "description": "Whether everything the server did fits what it says it is for."},
    "instructsModel": {"type": "boolean", "description": "Whether any server text tries to instruct the model that uses it."},
    "findings": {"type": "array", "maxItems": 20, "items": ` + findingSchema + `},
    "expectedHosts": {
      "type": "array", "maxItems": 20,
      "description": "The hosts the stated purpose needs the server to reach, such as api.github.com.",
      "items": {"type": "string", "maxLength": 253}
    }
  }
}`

// MoveSchema is the JSON Schema of the next_move tool's input.
const MoveSchema = `{
  "type": "object",
  "additionalProperties": false,
  "required": ["action", "arguments", "reason"],
  "properties": {
    "action": {"enum": ["call", "read_source", "inspect_download", "clock", "ask_human", "done"]},
    "arguments": {
      "type": "object",
      "description": "call: {\"tool\": <name>, \"arguments\": {...}}; read_source: {\"path\": <a file the harness named>}; inspect_download: {\"path\": <a file the server wrote>}; clock: {\"offset\": \"720h\"}; ask_human and done: {}."
    },
    "reason": {"type": "string", "maxLength": 1000},
    "verdict": {"enum": ["pass", "review", "block"], "description": "With done: the verdict the investigation supports."},
    "findings": {"type": "array", "maxItems": 20, "items": ` + findingSchema + `}
  }
}`

// strictDecode decodes raw into v, refusing unknown fields.
func strictDecode(raw json.RawMessage, v any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("%w: %w", ErrBadAnswer, err)
	}
	if dec.More() {
		return fmt.Errorf("%w: more than one value", ErrBadAnswer)
	}
	return nil
}

// DecodeProbes reads a write_probes answer for a listing of n tools.
func DecodeProbes(raw json.RawMessage, n int) ([]ProbeArgs, error) {
	var a struct {
		Probes []ProbeArgs `json:"probes"`
	}
	if err := strictDecode(raw, &a); err != nil {
		return nil, err
	}
	for _, p := range a.Probes {
		if p.Tool < 0 || p.Tool >= n || p.Arguments == nil {
			return nil, fmt.Errorf("%w: a probe names tool %d of %d, or has no arguments", ErrBadAnswer, p.Tool, n)
		}
		if sizeOf(p.Arguments) > maxProbeArgsBytes {
			return nil, fmt.Errorf("%w: the arguments of tool %d are over %d bytes", ErrBadAnswer, p.Tool, maxProbeArgsBytes)
		}
	}
	return a.Probes, nil
}

type modelFinding struct {
	Rule     string `json:"rule"`
	Evidence string `json:"evidence"`
}

var modelRules = []string{RulePurposeMismatch, RuleInstructsModel, RuleJudgeConcern}

func toFindings(in []modelFinding) ([]findings.Finding, error) {
	if len(in) > maxModelFindings {
		return nil, fmt.Errorf("%w: %d findings", ErrBadAnswer, len(in))
	}
	out := make([]findings.Finding, 0, len(in))
	for _, f := range in {
		if !slices.Contains(modelRules, f.Rule) || len(f.Evidence) > maxEvidenceLength {
			return nil, fmt.Errorf("%w: a finding of rule %q", ErrBadAnswer, f.Rule)
		}
		out = append(out, findings.Finding{Source: findings.Model, Rule: f.Rule, Evidence: f.Evidence})
	}
	return out, nil
}

func validVerdict(v verdict.Verdict, optional bool) bool {
	return v == verdict.Pass || v == verdict.Review || v == verdict.Block || (optional && v == "")
}

// hostPattern is a lowercase DNS name: what an egress allowlist takes.
var hostPattern = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$`)

// DecodeJudgement reads a judge_server answer. A server that doesn't fit
// its purpose, or whose text instructs the model, is a finding even when
// the judge listed none.
func DecodeJudgement(raw json.RawMessage) (Judgement, error) {
	var a struct {
		Verdict        verdict.Verdict `json:"verdict"`
		FitsPurpose    *bool           `json:"fitsPurpose"`
		InstructsModel *bool           `json:"instructsModel"`
		Findings       []modelFinding  `json:"findings"`
		ExpectedHosts  []string        `json:"expectedHosts"`
	}
	if err := strictDecode(raw, &a); err != nil {
		return Judgement{}, err
	}
	if !validVerdict(a.Verdict, false) || a.FitsPurpose == nil || a.InstructsModel == nil {
		return Judgement{}, fmt.Errorf("%w: no verdict, fitsPurpose or instructsModel", ErrBadAnswer)
	}
	fs, err := toFindings(a.Findings)
	if err != nil {
		return Judgement{}, err
	}
	has := func(rule string) bool {
		return slices.ContainsFunc(fs, func(f findings.Finding) bool { return f.Rule == rule })
	}
	if !*a.FitsPurpose && !has(RulePurposeMismatch) {
		fs = append(fs, findings.Finding{Source: findings.Model, Rule: RulePurposeMismatch, Evidence: "the judge found the behaviour doesn't fit the stated purpose"})
	}
	if *a.InstructsModel && !has(RuleInstructsModel) {
		fs = append(fs, findings.Finding{Source: findings.Model, Rule: RuleInstructsModel, Evidence: "the judge found server text that instructs the model"})
	}
	if len(a.ExpectedHosts) > maxHosts {
		return Judgement{}, fmt.Errorf("%w: %d hosts", ErrBadAnswer, len(a.ExpectedHosts))
	}
	hosts := []string{}
	for _, h := range a.ExpectedHosts {
		if !hostPattern.MatchString(h) {
			return Judgement{}, fmt.Errorf("%w: %q is not a host name", ErrBadAnswer, h)
		}
		if !slices.Contains(hosts, h) {
			hosts = append(hosts, h)
		}
	}
	return Judgement{Verdict: a.Verdict, Findings: fs, ExpectedHosts: hosts}, nil
}

// moveActions are the actions the judge may pick, and the registered
// action each runs. ask_human and done end the investigation.
var moveActions = map[string]Action{
	string(ActCall):            ActCall,
	string(ActReadSource):      ActReadSource,
	string(ActInspectDownload): ActInspectDownload,
	string(ActClock):           ActClock,
	string(ActAskHuman):        ActAskHuman,
	MoveDone:                   "",
}

// DecodeMove reads a next_move answer. Each action's arguments are checked
// by the action itself before anything runs.
func DecodeMove(raw json.RawMessage) (Move, error) {
	var a struct {
		Action    string          `json:"action"`
		Arguments json.RawMessage `json:"arguments"`
		Reason    string          `json:"reason"`
		Verdict   verdict.Verdict `json:"verdict"`
		Findings  []modelFinding  `json:"findings"`
	}
	if err := strictDecode(raw, &a); err != nil {
		return Move{}, err
	}
	if _, ok := moveActions[a.Action]; !ok {
		return Move{}, fmt.Errorf("%w: the action %q is not one the judge may pick", ErrBadAnswer, a.Action)
	}
	if !validVerdict(a.Verdict, true) || len(a.Reason) > maxEvidenceLength || len(a.Arguments) > maxProbeArgsBytes {
		return Move{}, fmt.Errorf("%w: the move's verdict, reason or arguments", ErrBadAnswer)
	}
	if len(a.Arguments) == 0 || a.Arguments[0] != '{' {
		return Move{}, fmt.Errorf("%w: the move's arguments are not an object", ErrBadAnswer)
	}
	fs, err := toFindings(a.Findings)
	if err != nil {
		return Move{}, err
	}
	return Move{Action: a.Action, Arguments: a.Arguments, Reason: a.Reason, Verdict: a.Verdict, Findings: fs}, nil
}
