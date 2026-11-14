package harness

import "github.com/JairJosafath/mcp-customs/src/internal/demoproxy"

// goProxyEnv is what a Go install's environment needs to resolve through
// list, a GOPROXY-style list such as the stack's demo proxy and then the
// public one: the list, and the checksum database skipped for the demo
// modules alone, which the public database has never seen. Every other
// module is still checked against it. An empty list keeps Go's defaults.
func goProxyEnv(list string) []string {
	if list == "" {
		return nil
	}
	return []string{"GOPROXY=" + list, "GONOSUMDB=" + demoproxy.ModulePrefix}
}
