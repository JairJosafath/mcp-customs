package harness

import (
	"net/http"
	"strings"
)

// refuseOwnAPI answers 403 when hosts names the stack's own API host, which
// the server under test may never reach: the Checker refuses it first, and
// this is the second check. It answers 0 when there is nothing to refuse.
func (h *Harness) refuseOwnAPI(hosts []string) (int, answer) {
	api := normalHost(h.cfg.APIHost)
	for _, host := range hosts {
		if api != "" && normalHost(host) == api {
			return problem(http.StatusForbidden, "The stack's own API host is never allowed.")
		}
	}
	return 0, nil
}

// normalHost is a host name as DNS compares it: lowercase, without a
// trailing dot.
func normalHost(host string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
}
