package egress

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"strconv"
	"sync/atomic"
	"syscall"
)

// An NFLog reads the packets the firewall refuses and logs to its NFLOG
// group: every packet of the server's that is neither DNS nor TCP (which
// the proxy and the catcher see), and all of its IPv6. Opening one needs
// CAP_NET_ADMIN.
type NFLog struct {
	fd    int
	group uint16
	// file holds fd once it is configured, on Go's poller, so that Close
	// wakes a read blocked on it.
	file   *os.File
	raw    syscall.RawConn
	closed atomic.Bool
}

// Netlink and nfnetlink_log constants (linux/netfilter/nfnetlink_log.h).
const (
	netlinkNetfilter = 12
	nfnlSubsysULOG   = 4
	nfulnlMsgPacket  = 0
	nfulnlMsgConfig  = 1
	nfulaCfgCmd      = 1
	nfulaCfgMode     = 2
	nfulaPayload     = 9
	nfulaCfgQThresh  = 5
	nfulnlCfgCmdBind = 1
	nfulnlCopyPacket = 2
	nlmsgHeaderLen   = 16
	nfgenmsgLen      = 4
	nlaHeaderLen     = 4
	nlmsgError       = 2
	nlmsgDone        = 3
	copyRange        = 0xffff
	// nflogReceiveBuffer holds about a thousand full-size packets.
	nflogReceiveBuffer = 64 << 20
)

// OpenNFLog binds to the NFLOG group and asks for whole packets.
func OpenNFLog(group uint16) (*NFLog, error) {
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC, netlinkNetfilter)
	if err != nil {
		return nil, fmt.Errorf("open a netfilter netlink socket: %w", err)
	}
	n := &NFLog{fd: fd, group: group}
	if err := syscall.Bind(fd, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}); err != nil {
		_ = n.Close()
		return nil, fmt.Errorf("bind the netlink socket: %w", err)
	}
	// SO_RCVBUFFORCE passes the system's rmem_max; it needs CAP_NET_ADMIN,
	// which binding the group needs too.
	if err := syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_RCVBUFFORCE, nflogReceiveBuffer); err != nil {
		_ = n.Close()
		return nil, fmt.Errorf("size the netlink socket's buffer: %w", err)
	}
	bind := nla(nfulaCfgCmd, []byte{nfulnlCfgCmdBind})
	mode := make([]byte, 6)
	binary.BigEndian.PutUint32(mode, copyRange)
	mode[4] = nfulnlCopyPacket
	// One packet per message, sent at once rather than batched for a second.
	qthresh := binary.BigEndian.AppendUint32(nil, 1)
	for _, attr := range [][]byte{bind, nla(nfulaCfgMode, mode), nla(nfulaCfgQThresh, qthresh)} {
		if err := n.configure(attr); err != nil {
			_ = n.Close()
			return nil, err
		}
	}
	if err := syscall.SetNonblock(fd, true); err != nil {
		_ = n.Close()
		return nil, fmt.Errorf("make the netlink socket non-blocking: %w", err)
	}
	n.file = os.NewFile(uintptr(fd), "nflog")
	raw, err := n.file.SyscallConn()
	if err != nil {
		_ = n.Close()
		return nil, fmt.Errorf("poll the netlink socket: %w", err)
	}
	n.raw = raw
	return n, nil
}

// read reads one datagram into buf, waiting on Go's poller.
func (n *NFLog) read(buf []byte) (int, error) {
	var got int
	var rerr error
	err := n.raw.Read(func(fd uintptr) bool {
		got, _, rerr = syscall.Recvfrom(int(fd), buf, 0)
		return !errors.Is(rerr, syscall.EAGAIN)
	})
	if err != nil {
		return 0, err
	}
	return got, rerr
}

// configure sends one config message for the group and waits for its ack.
func (n *NFLog) configure(attr []byte) error {
	msg := make([]byte, nlmsgHeaderLen+nfgenmsgLen, nlmsgHeaderLen+nfgenmsgLen+len(attr))
	msg = append(msg, attr...)
	binary.NativeEndian.PutUint32(msg[0:], uint32(len(msg))) //nolint:gosec // a config message of a few dozen bytes
	binary.NativeEndian.PutUint16(msg[4:], nfnlSubsysULOG<<8|nfulnlMsgConfig)
	binary.NativeEndian.PutUint16(msg[6:], syscall.NLM_F_REQUEST|syscall.NLM_F_ACK)
	binary.NativeEndian.PutUint32(msg[8:], 1)
	msg[16] = syscall.AF_UNSPEC
	binary.BigEndian.PutUint16(msg[18:], n.group)
	if err := syscall.Sendto(n.fd, msg, 0, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}); err != nil {
		return fmt.Errorf("configure NFLOG group %d: %w", n.group, err)
	}
	buf := make([]byte, 4096)
	got, _, err := syscall.Recvfrom(n.fd, buf, 0)
	if err != nil {
		return fmt.Errorf("read NFLOG group %d's answer: %w", n.group, err)
	}
	for _, m := range messages(buf[:got]) {
		if m.kind == nlmsgError && len(m.body) >= 4 {
			// The kernel answers 0, or a negative errno, as an int32.
			if v := binary.NativeEndian.Uint32(m.body); v != 0 {
				return fmt.Errorf("configure NFLOG group %d: %w", n.group, syscall.Errno(^v+1))
			}
		}
	}
	return nil
}

// Close stops the log; a Serve reading it returns.
func (n *NFLog) Close() error {
	n.closed.Store(true)
	if n.file != nil {
		return n.file.Close()
	}
	return syscall.Close(n.fd)
}

// ServeNFLog records each packet n reads as a refused direct connect
// observation, with the canaries in its payload, until n is closed. If it
// stops before, it records that it stopped: what is refused after goes
// unread.
func (e *Egress) ServeNFLog(n *NFLog) error {
	buf := make([]byte, 1<<17)
	for {
		got, err := n.read(buf)
		switch {
		case errors.Is(err, syscall.EINTR):
			continue
		case errors.Is(err, syscall.ENOBUFS):
			// The queue overflowed: the kernel dropped packets unread, how
			// many it doesn't say.
			e.recordDropped(ConnectDetail{}, 1)
			continue
		case err != nil && n.closed.Load():
			return nil
		case err != nil:
			err = fmt.Errorf("read NFLOG group %d: %w", n.group, err)
			e.recordStopped(ConnectDetail{}, err.Error())
			return err
		case got == 0:
			if !n.closed.Load() {
				e.recordStopped(ConnectDetail{}, fmt.Sprintf("NFLOG group %d closed", n.group))
			}
			return nil
		}
		for _, m := range messages(buf[:got]) {
			if m.kind != nfnlSubsysULOG<<8|nfulnlMsgPacket || len(m.body) < nfgenmsgLen {
				continue
			}
			payload := attribute(m.body[nfgenmsgLen:], nfulaPayload)
			if d, data, ok := refusedPacket(payload); ok {
				d.Host = e.fakeName(d.Address)
				if found := e.match(data); len(found) > 0 {
					d.Canaries = found
				}
				e.recordDirect(d)
			}
		}
	}
}

type netlinkMessage struct {
	kind uint16
	body []byte
}

// messages splits a netlink datagram into its messages.
func messages(b []byte) []netlinkMessage {
	var out []netlinkMessage
	for len(b) >= nlmsgHeaderLen {
		size := int(binary.NativeEndian.Uint32(b))
		if size < nlmsgHeaderLen || size > len(b) {
			break
		}
		out = append(out, netlinkMessage{kind: binary.NativeEndian.Uint16(b[4:]), body: b[nlmsgHeaderLen:size]})
		b = b[align(size):]
	}
	return out
}

// attribute is the value of the first netlink attribute of kind in b.
func attribute(b []byte, kind uint16) []byte {
	for len(b) >= nlaHeaderLen {
		size := int(binary.NativeEndian.Uint16(b))
		if size < nlaHeaderLen || size > len(b) {
			return nil
		}
		if binary.NativeEndian.Uint16(b[2:])&0x3fff == kind {
			return b[nlaHeaderLen:size]
		}
		b = b[min(align(size), len(b)):]
	}
	return nil
}

// nla is a netlink attribute, padded.
func nla(kind uint16, value []byte) []byte {
	out := make([]byte, align(nlaHeaderLen+len(value)))
	binary.NativeEndian.PutUint16(out, uint16(nlaHeaderLen+len(value))) //nolint:gosec // the config attributes are a few bytes
	binary.NativeEndian.PutUint16(out[2:], kind)
	copy(out[nlaHeaderLen:], value)
	return out
}

func align(n int) int { return (n + 3) &^ 3 }

// IP protocol numbers the observations name.
const (
	protoICMP   = 1
	protoTCP    = 6
	protoUDP    = 17
	protoICMPv6 = 58
)

// refusedPacket reads an IPv4 or IPv6 packet: where it was headed, and its
// transport payload, which is searched for canaries.
func refusedPacket(p []byte) (ConnectDetail, []byte, bool) {
	if len(p) < 1 {
		return ConnectDetail{}, nil, false
	}
	var proto int
	var dst netip.Addr
	var rest []byte
	switch p[0] >> 4 {
	case 4:
		ihl := int(p[0]&0x0f) * 4
		if len(p) < 20 || ihl < 20 || len(p) < ihl {
			return ConnectDetail{}, nil, false
		}
		proto, dst, rest = int(p[9]), netip.AddrFrom4([4]byte(p[16:20])), p[ihl:]
	case 6:
		if len(p) < 40 {
			return ConnectDetail{}, nil, false
		}
		proto, dst, rest = int(p[6]), netip.AddrFrom16([16]byte(p[24:40])), p[40:]
	default:
		return ConnectDetail{}, nil, false
	}
	d := ConnectDetail{Address: dst.String(), Via: "direct", Refused: true, Proto: protoName(proto)}
	switch proto {
	case protoTCP:
		if len(rest) >= 20 {
			d.Port = int(binary.BigEndian.Uint16(rest[2:]))
			off := int(rest[12]>>4) * 4
			rest = rest[min(off, len(rest)):]
		}
	case protoUDP:
		if len(rest) >= 8 {
			d.Port = int(binary.BigEndian.Uint16(rest[2:]))
			rest = rest[8:]
		}
	}
	return d, rest, true
}

func protoName(p int) string {
	switch p {
	case protoICMP:
		return "icmp"
	case protoTCP:
		return "tcp"
	case protoUDP:
		return "udp"
	case protoICMPv6:
		return "icmpv6"
	}
	return strconv.Itoa(p)
}
