package harness

import (
	"context"
	"net/http"

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

// checkHosts refuses anything in hosts that is not a plain ASCII host
// name (ownapi.ValidHost): a URL, a port, an IP address in any form, and
// any name a transport's IDNA mapping could turn into the API's own.
func checkHosts(hosts []string) error {
	for _, host := range hosts {
		if err := ownapi.ValidHost(host); err != nil {
			return err
		}
	}
	return nil
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
