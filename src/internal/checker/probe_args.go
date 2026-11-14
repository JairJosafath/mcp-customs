package checker

import (
	"math"
	"reflect"
	"slices"
)

// argumentsFor are the arguments to probe t with: the judge's, limited to
// t's input schema. A property the schema doesn't name is dropped; one the
// judge gave a value its schema doesn't allow is left out, and a required
// one left out gets the stub of its type. Canaries are the judge's to
// plant: code doesn't put a secret where the server didn't ask for one.
func argumentsFor(t tool, model map[string]any) map[string]any {
	stubs := stubArguments(t)
	args := map[string]any{}
	for name, p := range t.InputSchema.Properties {
		v, ok := model[name]
		if ok && fitsType(p.Type, v) && (len(p.Enum) == 0 || slices.ContainsFunc(p.Enum, func(e any) bool { return reflect.DeepEqual(e, v) })) {
			args[name] = v
		} else if slices.Contains(t.InputSchema.Required, name) {
			args[name] = stubs[name]
		}
	}
	return args
}

// fitsType says whether v, decoded from JSON, is of the schema type typ:
// a name, a list of names, or none, which allows anything.
func fitsType(typ, v any) bool {
	switch t := typ.(type) {
	case nil:
		return true
	case string:
		return isJSONType(t, v)
	case []any:
		return slices.ContainsFunc(t, func(e any) bool {
			name, _ := e.(string)
			return isJSONType(name, v)
		})
	}
	return false
}

func isJSONType(name string, v any) bool {
	switch name {
	case "string":
		_, ok := v.(string)
		return ok
	case "number":
		_, ok := v.(float64)
		return ok
	case "integer":
		f, ok := v.(float64)
		return ok && f == math.Trunc(f)
	case "boolean":
		_, ok := v.(bool)
		return ok
	case "array":
		_, ok := v.([]any)
		return ok
	case "object":
		_, ok := v.(map[string]any)
		return ok
	case "null":
		return v == nil
	}
	return false
}
