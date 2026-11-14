package egress

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"syscall"
	"time"
)

// An OriginalDestination tells where a connection the firewall redirected
// was headed.
type OriginalDestination func(net.Conn) (netip.AddrPort, error)

// Bounds on what the catcher reads of a direct connection.
const (
	// catchRead is how much of a connection's payload is searched.
	catchRead = 64 << 10
	// catchWait is how long the catcher waits for that payload.
	catchWait = time.Second
	// maxCatching bounds the connections read at once; more wait their turn.
	maxCatching = 64
)

// ServeCatch turns away, on l, every direct connection the firewall
// redirected there: TCP the server sent anywhere but the proxy. It reads
// what each sends, for catchWait or up to catchRead bytes, and records it
// as a connect observation naming where it was headed and the canaries in
// its payload, then resets it. It returns when l is closed, once every
// connection is recorded.
func (e *Egress) ServeCatch(l net.Listener, dst OriginalDestination) error {
	var wg sync.WaitGroup
	defer wg.Wait()
	slots := make(chan struct{}, maxCatching)
	for {
		conn, err := l.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		d := ConnectDetail{Proto: "tcp", Via: "direct", Refused: true}
		if to, err := dst(conn); err == nil {
			d.Address = to.Addr().String()
			d.Port = int(to.Port())
			d.Host = e.fakeName(d.Address)
		}
		slots <- struct{}{}
		wg.Go(func() {
			defer func() { <-slots }()
			e.catch(conn, d)
		})
	}
}

// catch reads what conn sends, records it as d with its canaries, and
// resets it.
func (e *Egress) catch(conn net.Conn, d ConnectDetail) {
	_ = conn.SetReadDeadline(time.Now().Add(catchWait))
	// A deadline or reset ends the read; what came before it is searched.
	payload, _ := io.ReadAll(io.LimitReader(conn, catchRead))
	if found := e.match(payload); len(found) > 0 {
		d.Canaries = found
	}
	e.recordDirect(d)
	reset(conn)
}

// reset closes conn so the client sees the connection refused, reset
// rather than closed in order.
func reset(conn net.Conn) {
	if tcp, ok := conn.(*net.TCPConn); ok {
		_ = tcp.SetLinger(0)
	}
	_ = conn.Close()
}

// soOriginalDst is Linux's SO_ORIGINAL_DST, at level SOL_IP.
const soOriginalDst = 80

// RedirectedFrom is the OriginalDestination of a connection netfilter's
// REDIRECT target sent here: SO_ORIGINAL_DST on its socket.
func RedirectedFrom(conn net.Conn) (netip.AddrPort, error) {
	tcp, ok := conn.(*net.TCPConn)
	if !ok {
		return netip.AddrPort{}, errors.New("not a TCP connection")
	}
	raw, err := tcp.SyscallConn()
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("reach the socket: %w", err)
	}
	var addr netip.AddrPort
	var sockErr error
	err = raw.Control(func(fd uintptr) {
		// sockaddr_in comes back in the 16 bytes of an ipv6_mreq.
		mreq, err := syscall.GetsockoptIPv6Mreq(int(fd), syscall.IPPROTO_IP, soOriginalDst)
		if err != nil {
			sockErr = err
			return
		}
		b := mreq.Multiaddr
		addr = netip.AddrPortFrom(netip.AddrFrom4([4]byte{b[4], b[5], b[6], b[7]}), uint16(b[2])<<8|uint16(b[3]))
	})
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("reach the socket: %w", err)
	}
	if sockErr != nil {
		return netip.AddrPort{}, fmt.Errorf("read where the connection was headed: %w", sockErr)
	}
	return addr, nil
}
