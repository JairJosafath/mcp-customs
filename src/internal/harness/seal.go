package harness

import "net/http"

// seal ends the run's egress for good: the allowlist is emptied and every
// new connection refused, so nothing the server sends after leaves the
// sandbox. The Checker seals before its last read of the observations.
// Sealing again answers the same.
func (h *Harness) seal(r *http.Request) (int, answer) {
	var req struct{}
	if err := decode(r, &req); err != nil {
		return problem(http.StatusBadRequest, err.Error())
	}
	if h.cfg.Egress == nil {
		return problem(http.StatusConflict, "This harness has no egress proxy.")
	}
	h.cfg.Egress.Seal()
	h.sealed = true
	return http.StatusOK, answer{"hosts": []string{}}
}
