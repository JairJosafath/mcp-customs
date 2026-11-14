package egress

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"syscall"
)

// An OriginalDestination tells where a connection the firewall redirected
// was headed.
type OriginalDestination func(net.Conn) (netip.AddrPort, error)

// ServeCatch turns away, on l, every direct connection the firewall
// redirected there: TCP the server sent anywhere but the proxy. Each
// becomes a connect observation naming where it was headed, and is reset.
// It returns when l is closed.
func (e *Egress) ServeCatch(l net.Listener, dst OriginalDestination) error {
	for {
		conn, err := l.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		d := ConnectDetail{Via: "direct", Refused: true}
		if to, err := dst(conn); err == nil {
			d.Address = to.Addr().String()
			d.Port = int(to.Port())
			d.Host = e.fakeName(d.Address)
		}
		e.record(KindConnect, d)
		reset(conn)
	}
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
