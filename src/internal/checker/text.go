package checker

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"

	"github.com/JairJosafath/mcp-customs/src/internal/findings"
)

// scanJSON scans every string of a JSON value with findings.ScanText, and
// names where it came from in each finding's evidence.
func scanJSON(where string, raw json.RawMessage) []findings.Finding {
	found := findings.ScanText(findings.JSONStrings(raw)).Findings
	for i := range found {
		found[i].Evidence = fmt.Sprintf("%s: %s", where, found[i].Evidence)
	}
	return found
}

// toolListHash is the SHA-256 of the tool list, whole schemas included, in
// a canonical form: each tool's JSON with its keys sorted, the tools
// sorted. The same tools in another order or spacing hash the same.
func toolListHash(tools []json.RawMessage) (string, error) {
	canonical := make([][]byte, 0, len(tools))
	for i, t := range tools {
		var v any
		if err := json.Unmarshal(t, &v); err != nil {
			return "", fmt.Errorf("read tool %d of the list: %w", i, err)
		}
		b, err := json.Marshal(v)
		if err != nil {
			return "", fmt.Errorf("encode tool %d of the list: %w", i, err)
		}
		canonical = append(canonical, b)
	}
	slices.SortFunc(canonical, bytes.Compare)
	sum := sha256.Sum256(append(append([]byte{'['}, bytes.Join(canonical, []byte{','})...), ']'))
	return hex.EncodeToString(sum[:]), nil
}

// tool is the part of a listed tool a probe needs.
type tool struct {
	Name        string `json:"name"`
	InputSchema struct {
		Properties map[string]struct {
			Type any   `json:"type"`
			Enum []any `json:"enum"`
		} `json:"properties"`
		Required []string `json:"required"`
	} `json:"inputSchema"`
}

// stubArguments are placeholder arguments for a tool, one per property of
// its input schema: the first enum value, or a value of the property's
// type: what a tool is probed with when the judge wrote none.
func stubArguments(t tool) map[string]any {
	args := map[string]any{}
	for name, p := range t.InputSchema.Properties {
		if len(p.Enum) > 0 {
			args[name] = p.Enum[0]
			continue
		}
		typ, _ := p.Type.(string)
		if list, ok := p.Type.([]any); ok && len(list) > 0 {
			typ, _ = list[0].(string)
		}
		args[name] = stubOf(typ)
	}
	return args
}

func stubOf(typ string) any {
	switch typ {
	case "integer", "number":
		return 1
	case "boolean":
		return true
	case "array":
		return []any{}
	case "object":
		return map[string]any{}
	case "null":
		return nil
	default:
		return "test"
	}
}
