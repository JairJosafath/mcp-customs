package checker

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/JairJosafath/mcp-customs/src/internal/findings"
	"github.com/JairJosafath/mcp-customs/src/internal/verdict"
)

func TestEachSchemaIsJSON(t *testing.T) {
	for name, schema := range map[string]string{ToolProbes: ProbesSchema, ToolJudgement: JudgementSchema, ToolMove: MoveSchema} {
		var v map[string]any
		if err := json.Unmarshal([]byte(schema), &v); err != nil || v["additionalProperties"] != any(false) {
			t.Errorf("%s: %v, %v; want an object schema that refuses unknown fields", name, err, v["additionalProperties"])
		}
	}
}

func TestAnAnswerOutsideItsSchemaIsRefused(t *testing.T) {
	long := strings.Repeat("x", maxEvidenceLength+1)
	for name, decode := range map[string]func() error{
		"probes: an unknown field": func() error { _, err := DecodeProbes(json.RawMessage(`{"probes":[],"note":"hi"}`), 1); return err },
		"probes: a tool not listed": func() error {
			_, err := DecodeProbes(json.RawMessage(`{"probes":[{"tool":3,"arguments":{}}]}`), 1)
			return err
		},
		"probes: arguments too large": func() error {
			_, err := DecodeProbes(json.RawMessage(`{"probes":[{"tool":0,"arguments":{"a":"`+strings.Repeat("x", maxProbeArgsBytes)+`"}}]}`), 1)
			return err
		},
		"judgement: no fitsPurpose": func() error {
			_, err := DecodeJudgement(json.RawMessage(`{"verdict":"pass","instructsModel":false,"findings":[],"expectedHosts":[]}`))
			return err
		},
		"judgement: a verdict it can't give": func() error {
			_, err := DecodeJudgement(json.RawMessage(`{"verdict":"approved","fitsPurpose":true,"instructsModel":false,"findings":[],"expectedHosts":[]}`))
			return err
		},
		"judgement: a code rule": func() error {
			_, err := DecodeJudgement(json.RawMessage(`{"verdict":"pass","fitsPurpose":true,"instructsModel":false,"findings":[{"rule":"canary-left","evidence":"x"}],"expectedHosts":[]}`))
			return err
		},
		"judgement: a host that isn't one": func() error {
			_, err := DecodeJudgement(json.RawMessage(`{"verdict":"pass","fitsPurpose":true,"instructsModel":false,"findings":[],"expectedHosts":["*.example.com"]}`))
			return err
		},
		"judgement: evidence too long": func() error {
			_, err := DecodeJudgement(json.RawMessage(`{"verdict":"pass","fitsPurpose":true,"instructsModel":false,"findings":[{"rule":"judge-concern","evidence":"` + long + `"}],"expectedHosts":[]}`))
			return err
		},
		"move: an unregistered action": func() error { _, err := DecodeMove(fixture("move_unregistered")); return err },
		"move: arguments not an object": func() error {
			_, err := DecodeMove(json.RawMessage(`{"action":"call","arguments":"get_forecast","reason":"x"}`))
			return err
		},
		"move: two values": func() error {
			_, err := DecodeMove(json.RawMessage(`{"action":"done","arguments":{},"reason":"x"} {}`))
			return err
		},
	} {
		if err := decode(); !errors.Is(err, ErrBadAnswer) {
			t.Errorf("%s: %v, want ErrBadAnswer", name, err)
		}
	}
}

func TestAJudgementSaysWhatItFoundAsModelFindings(t *testing.T) {
	j, err := DecodeJudgement(json.RawMessage(`{"verdict":"pass","fitsPurpose":false,"instructsModel":true,"findings":[],"expectedHosts":["api.github.com","api.github.com"]}`))
	if err != nil {
		t.Fatal(err)
	}
	var rules []string
	for _, f := range j.Findings {
		if f.Source != findings.Model {
			t.Errorf("finding %+v is not the model's", f)
		}
		rules = append(rules, f.Rule)
	}
	if !reflect.DeepEqual(rules, []string{RulePurposeMismatch, RuleInstructsModel}) || !reflect.DeepEqual(j.ExpectedHosts, []string{"api.github.com"}) {
		t.Errorf("judgement %+v, want both findings and one host", j)
	}
	if got := verdict.Decide(verdict.Input{Model: j.Findings, ModelVerdict: j.Verdict}).Verdict; got != verdict.Review {
		t.Errorf("decided %s, want review", got)
	}
}

func TestTheWeatherMoveDecodesToACallWithTheKey(t *testing.T) {
	m, err := DecodeMove(fixture("move_probe_with_key"))
	if err != nil {
		t.Fatal(err)
	}
	var a callArgs
	if m.Action != string(ActCall) || json.Unmarshal(m.Arguments, &a) != nil || a.Tool != "get_forecast" || a.Arguments["auth_context"] != fixedCanaries.Get("ssh-private-key") {
		t.Errorf("move %+v, want a call of get_forecast with the SSH canary", m)
	}
}

func TestProbeArgumentsKeepOnlyWhatTheSchemaAllows(t *testing.T) {
	var tl tool
	if err := json.Unmarshal([]byte(`{"name":"t","inputSchema":{"properties":{"n":{"type":"integer"},"s":{"type":["string","null"]},"e":{"enum":["a","b"]},"any":{}},"required":["n","e"]}}`), &tl); err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct {
		model, want map[string]any
	}{
		"all fit":               {map[string]any{"n": 2.0, "s": nil, "e": "b", "any": []any{1.0}}, map[string]any{"n": 2.0, "s": nil, "e": "b", "any": []any{1.0}}},
		"wrong types are stubs": {map[string]any{"n": 2.5, "s": 3.0, "e": "c"}, map[string]any{"n": 1, "e": "a"}},
		"unknown are dropped":   {map[string]any{"n": 1.0, "e": "a", "x": "y"}, map[string]any{"n": 1.0, "e": "a"}},
	} {
		if got := argumentsFor(tl, tc.model); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%s: %v, want %v", name, got, tc.want)
		}
	}
}
