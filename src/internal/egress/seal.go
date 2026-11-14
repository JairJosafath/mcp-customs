package egress

import (
	"bytes"
	"context"
	"net/http"
	"net/url"
)

// Seal ends the run's egress for good: the allowlist is emptied, the
// registries with it, every request still being sent on is cut, and every
// new tunnel is refused. DNS is still answered, with fakes, and every
// request is still searched and recorded, so what the server tries after
// is seen; nothing it sends leaves. It returns only once every request
// allowed before it is done, recorded and cut, so none reaches its host
// after. Sealing again does nothing.
func (e *Egress) Seal() {
	e.mu.Lock()
	e.allowed = map[string]bool{}
	e.install = map[string]bool{}
	e.installGet = map[string][]string{}
	e.installing = false
	e.seal()
	e.mu.Unlock()
	// No request is admitted from here on, so only those admitted before
	// are waited for: each is recorded, and cut, by the time Seal returns.
	e.inflight.Wait()
}

// isSealed says whether Seal has run.
func (e *Egress) isSealed() bool {
	return e.sealed.Err() != nil
}

// admit decides, under the same lock Seal takes, whether a request of
// method for u on host may be sent on. One that may is in flight until done
// is called, and Seal waits for it. installGet says it may only as an
// install's GET under an InstallGet prefix (installGetLocked).
func (e *Egress) admit(method, host string, u *url.URL) (done func(), ok, installGet bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if !e.requestAllowedLocked(method, host, u) {
		return func() {}, false, false
	}
	h := normalHost(host)
	installGet = !e.allowed[h] && (!e.installing || !e.install[h])
	e.inflight.Add(1)
	return e.inflight.Done, true, installGet
}

// untilSealed is a context Seal cancels as it runs, not after, and that
// ends too when parent does. stop releases it.
func (e *Egress) untilSealed(parent context.Context) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(e.sealed)
	stop := context.AfterFunc(parent, cancel)
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
