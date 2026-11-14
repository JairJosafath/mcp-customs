package egress

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
)

// A Firewall is the netfilter rules that hold the server under test to the
// proxy. A Lambda MicroVM filters no hosts, so deny-by-default is enforced
// here, inside it: every packet the account's processes send, matched by
// their user ID, goes to the harness or nowhere.
//
//   - DNS (UDP port 53, to any address) is redirected to ServeDNS.
//   - TCP to the proxy passes.
//   - Any other TCP, to any address or port, is redirected to ServeCatch,
//     which records and refuses it.
//   - Anything else, and all IPv6, is rejected.
//
// Applying it needs CAP_NET_ADMIN: the harness runs as root, and the
// MicroVM image grants it (additionalOsCapabilities).
type Firewall struct {
	// Chain names the chains the rules live in, in the nat and filter
	// tables; OUTPUT jumps to them for the account's packets.
	Chain string
	// UID is the account the server runs as.
	UID uint32
	// The harness's ports on 127.0.0.1.
	ProxyPort, DNSPort, CatchPort int
}

// A Command is one iptables or ip6tables invocation.
type Command []string

// Rules are the commands that put the firewall up, in order.
func (f Firewall) Rules() []Command {
	uid := strconv.FormatUint(uint64(f.UID), 10)
	proxy, dns, catch := strconv.Itoa(f.ProxyPort), strconv.Itoa(f.DNSPort), strconv.Itoa(f.CatchPort)
	jump := []string{"-m", "owner", "--uid-owner", uid, "-j", f.Chain}
	return []Command{
		{"iptables", "-w", "-t", "nat", "-N", f.Chain},
		{"iptables", "-w", "-t", "nat", "-A", f.Chain, "-p", "udp", "--dport", "53", "-j", "REDIRECT", "--to-ports", dns},
		{"iptables", "-w", "-t", "nat", "-A", f.Chain, "-p", "tcp", "-d", "127.0.0.1", "--dport", proxy, "-j", "RETURN"},
		{"iptables", "-w", "-t", "nat", "-A", f.Chain, "-p", "tcp", "-j", "REDIRECT", "--to-ports", catch},
		append(Command{"iptables", "-w", "-t", "nat", "-I", "OUTPUT"}, jump...),
		{"iptables", "-w", "-t", "filter", "-N", f.Chain},
		// No "-o lo": a packet REDIRECT turned to 127.0.0.1 keeps the
		// interface it was first routed to.
		{"iptables", "-w", "-t", "filter", "-A", f.Chain, "-d", "127.0.0.1", "-p", "udp", "--dport", dns, "-j", "ACCEPT"},
		{"iptables", "-w", "-t", "filter", "-A", f.Chain, "-d", "127.0.0.1", "-p", "tcp", "--dport", proxy, "-j", "ACCEPT"},
		{"iptables", "-w", "-t", "filter", "-A", f.Chain, "-d", "127.0.0.1", "-p", "tcp", "--dport", catch, "-j", "ACCEPT"},
		{"iptables", "-w", "-t", "filter", "-A", f.Chain, "-j", "REJECT"},
		append(Command{"iptables", "-w", "-t", "filter", "-I", "OUTPUT"}, jump...),
		{"ip6tables", "-w", "-t", "filter", "-N", f.Chain},
		{"ip6tables", "-w", "-t", "filter", "-A", f.Chain, "-j", "REJECT"},
		append(Command{"ip6tables", "-w", "-t", "filter", "-I", "OUTPUT"}, jump...),
	}
}

// Teardown are the commands that take the firewall down again.
func (f Firewall) Teardown() []Command {
	uid := strconv.FormatUint(uint64(f.UID), 10)
	jump := []string{"-m", "owner", "--uid-owner", uid, "-j", f.Chain}
	var out []Command
	for _, t := range []struct{ bin, table string }{{"iptables", "nat"}, {"iptables", "filter"}, {"ip6tables", "filter"}} {
		out = append(out,
			append(Command{t.bin, "-w", "-t", t.table, "-D", "OUTPUT"}, jump...),
			Command{t.bin, "-w", "-t", t.table, "-F", f.Chain},
			Command{t.bin, "-w", "-t", t.table, "-X", f.Chain},
		)
	}
	return out
}

// A Runner runs one command to its end.
type Runner func(ctx context.Context, c Command) error

// Up puts the firewall up with run. If any rule fails, it takes down what
// it put up and returns why: the server must never run without it.
func (f Firewall) Up(ctx context.Context, run Runner) error {
	if f.Chain == "" || f.UID == 0 || f.ProxyPort == 0 || f.DNSPort == 0 || f.CatchPort == 0 {
		return errors.New("the firewall needs a chain, an unprivileged user ID and the harness's ports")
	}
	for _, c := range f.Rules() {
		if err := run(ctx, c); err != nil {
			f.Down(ctx, run)
			return fmt.Errorf("put the firewall up (%s): %w", strings.Join(c, " "), err)
		}
	}
	return nil
}

// Down takes the firewall down, as far as it is up.
func (f Firewall) Down(ctx context.Context, run Runner) {
	for _, c := range f.Teardown() {
		_ = run(ctx, c)
	}
}

// Exec is the Runner that runs c for real: iptables needs CAP_NET_ADMIN.
func Exec(ctx context.Context, c Command) error {
	if len(c) == 0 {
		return errors.New("no command to run")
	}
	out, err := exec.CommandContext(ctx, c[0], c[1:]...).CombinedOutput() //nolint:gosec // the firewall's own fixed commands
	if err != nil {
		return fmt.Errorf("%w: %s", err, out)
	}
	return nil
}
