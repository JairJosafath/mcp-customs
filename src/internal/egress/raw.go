package egress

import (
	"context"
	"fmt"
	"net"
	"slices"
	"sync"
)

// rawOverlap is how much of what a connection sent is searched again with
// the bytes after it, so a canary read in two pieces is still whole.
const rawOverlap = 64 << 10

// A rawConn keeps the bytes a client sends on a proxy connection, as sent,
// so what the HTTP parser drops or turns away is searched too: a chunk
// extension, a header or trailer too large, a body cut short or malformed,
// bytes that aren't HTTP. Each request takes the bytes read for it into
// what it searches (take); bytes no request took are searched and recorded
// when the connection closes, as unscanned, since the proxy couldn't read
// them as a request.
type rawConn struct {
	net.Conn
	e *Egress
	// host is the CONNECT host of a tunnel's connection.
	host string

	mu   sync.Mutex
	buf  []byte
	tail []byte
	over bool
	// done is set once the connection is handed off (a CONNECT, whose
	// tunnel is read on its own) or closed.
	done bool
}

func (e *Egress) newRawConn(c net.Conn, host string) *rawConn {
	return &rawConn{Conn: c, e: e, host: host}
}

func (c *rawConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.done && n > 0 {
		take := min(n, maxScan-len(c.buf))
		c.buf = append(c.buf, p[:take]...)
		c.over = c.over || take < n
	}
	return n, err
}

// take answers the bytes read since the last take, with the end of those
// before, and whether more were read than are kept.
func (c *rawConn) take() ([]byte, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	data := slices.Concat(c.tail, c.buf)
	over := c.over
	c.tail = append([]byte(nil), data[max(0, len(data)-rawOverlap):]...)
	c.buf, c.over = nil, false
	return data, over
}

// handOff answers what was read so far and stops keeping what is read.
func (c *rawConn) handOff() []byte {
	data, _ := c.take()
	c.mu.Lock()
	c.done = true
	c.mu.Unlock()
	return data
}

// Close closes the connection and records the bytes no request took.
func (c *rawConn) Close() error {
	err := c.Conn.Close()
	c.mu.Lock()
	done := c.done
	c.done = true
	left := len(c.buf)
	c.mu.Unlock()
	if done || left == 0 {
		return err
	}
	data, over := c.take()
	why := "the proxy could not read what was sent as an HTTP request; it was searched as sent"
	if over {
		why = fmt.Sprintf("the proxy could not read what was sent as an HTTP request; only its first %d MiB were searched as sent", maxScan>>20)
	}
	c.e.record(KindHTTP, HTTPDetail{Host: c.host, Canaries: c.e.match(data), Unscanned: why})
	return err
}

// rawListener hands out its connections as rawConns.
type rawListener struct {
	net.Listener
	e *Egress
}

func (l rawListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return l.e.newRawConn(c, ""), nil
}

type rawKey struct{}

// withRawConn is an http.Server's ConnContext: it puts the connection's
// rawConn, if it is one, in each request's context.
func withRawConn(ctx context.Context, c net.Conn) context.Context {
	if n, ok := c.(*closeNotifier); ok {
		c = n.Conn
	}
	if rc, ok := c.(*rawConn); ok {
		return context.WithValue(ctx, rawKey{}, rc)
	}
	return ctx
}

// rawConnOf is the rawConn a request came on, or nil.
func rawConnOf(ctx context.Context) *rawConn {
	rc, _ := ctx.Value(rawKey{}).(*rawConn)
	return rc
}
