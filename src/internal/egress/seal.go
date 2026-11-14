package egress

import (
	"bytes"
	"context"
	"net/http"
)

// Seal ends the run's egress for good: the allowlist is emptied, the
// registries with it, every request still being sent on is cut, and every
// new tunnel is refused. DNS is still answered, with fakes, and every
// request is still searched and recorded, so what the server tries after
// is seen; nothing it sends leaves. Sealing again does nothing.
func (e *Egress) Seal() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.allowed = map[string]bool{}
	e.install = map[string]bool{}
	e.installing = false
	e.seal()
}

// isSealed says whether Seal has run.
func (e *Egress) isSealed() bool {
	return e.sealed.Err() != nil
}

// untilSealed is ctx, cancelled too when the egress is sealed, so a request
// already being sent on is cut there. stop releases it.
func (e *Egress) untilSealed(ctx context.Context) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(e.sealed, cancel)
	return ctx, func() {
		stop()
		cancel()
	}
}

// refuseSealed answers a CONNECT that came after the seal: it is searched
// and recorded as refused, and no tunnel is made.
func (e *Egress) refuseSealed(w http.ResponseWriter, r *http.Request) {
	host, port := splitHostPort(r.Host, 443)
	var seen bytes.Buffer
	seen.WriteString(r.Host + "\n")
	_ = r.Header.Write(&seen)
	d := ConnectDetail{Host: host, Port: port, Via: "proxy", Refused: true}
	if found := e.match(seen.Bytes()); len(found) > 0 {
		d.Canaries = found
	}
	e.record(KindConnect, d)
	w.Header().Set("Connection", "close")
	http.Error(w, "egress is sealed", http.StatusForbidden)
}
