package findings

import (
	"encoding/json"
	"slices"
	"strings"
)

// JSONStrings is every string in a JSON value, keys and values, decoded,
// one a line: what a model reading the value would read. A value that
// isn't JSON is its own text.
func JSONStrings(raw json.RawMessage) string {
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return string(raw)
	}
	var b strings.Builder
	var walk func(any)
	walk = func(v any) {
		switch t := v.(type) {
		case string:
			b.WriteString(t)
			b.WriteByte('\n')
		case []any:
			for _, e := range t {
				walk(e)
			}
		case map[string]any:
			keys := make([]string, 0, len(t))
			for k := range t {
				keys = append(keys, k)
			}
			slices.Sort(keys)
			for _, k := range keys {
				b.WriteString(k)
				b.WriteByte('\n')
				walk(t[k])
			}
		}
	}
	walk(v)
	return b.String()
}
