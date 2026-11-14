package harness

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/JairJosafath/mcp-customs/src/internal/ownapi"
)

// refuseOwnAPI answers 403 when hosts names the stack's own API, in any of
// its forms, which the server under test may never reach: the Checker
// refuses it first, this is the second check, and the egress proxy's
// refusal of the API's addresses the third. It answers 0 when there is
// nothing to refuse.
func (h *Harness) refuseOwnAPI(hosts []string) (int, answer) {
	for _, host := range hosts {
		if h.api.IsHost(host) {
			return problem(http.StatusForbidden, "The stack's own API host is never allowed.")
		}
	}
	return 0, nil
}

// checkHosts refuses anything in hosts that is not a host name: a URL, a
// port, and an IP address in any form, which no name check could tell
// apart from the API's.
func checkHosts(hosts []string) error {
	for _, host := range hosts {
		if host == "" || strings.ContainsAny(host, "/ :@[]") {
			return fmt.Errorf("%q is not a host name", host)
		}
		if isAddress(host) {
			return fmt.Errorf("%q is an IP address; only host names are allowed", host)
		}
	}
	return nil
}

// isAddress says whether host reads as an IPv4 address in any of the forms
// resolvers accept (1.2.3.4, 1.2.3, 0x7f.1, 2130706433): its last label
// is a number, decimal or hex, which no top-level domain is.
func isAddress(host string) bool {
	labels := strings.Split(ownapi.NormalHost(host), ".")
	last := labels[len(labels)-1]
	digits := "0123456789"
	if hex, ok := strings.CutPrefix(last, "0x"); ok {
		last, digits = hex, "0123456789abcdef"
	}
	return last != "" && strings.Trim(last, digits) == ""
}

// installing runs the install with the proxy's install-time hosts open,
// and closes them however the install ends, a panic included.
func (h *Harness) installing(ctx context.Context, pkg Package) (Installed, error) {
	if h.cfg.Egress != nil {
		h.cfg.Egress.Installing(true)
		defer h.cfg.Egress.Installing(false)
	}
	return h.cfg.Installer.Install(ctx, pkg, h.sandbox())
}
