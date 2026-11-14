// Command harness serves the Harness API in the MicroVM: it installs and
// runs the server under test as an unprivileged user and reports what the
// server does. Wiring only; the work is in internal/harness.
//
// It reads HARNESS_TOKEN (the run's bearer token, required), HARNESS_USER
// (the unprivileged user, "dev" by default), HARNESS_WORKDIR (the server's
// working directory, ~/projects/server by default) and PORT (8080 by
// default). The token is removed from the environment once read. It must
// run as root, and refuses to start otherwise: it runs the server as the
// unprivileged user, never as itself.
//
// Before it answers anything it starts the egress proxy, writes the proxy
// CA's certificate (never its key) to /etc/mcp-customs, and puts up the
// firewall that holds the unprivileged user's traffic to the proxy; it
// refuses to start if any of that fails.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/JairJosafath/mcp-customs/src/internal/egress"
	"github.com/JairJosafath/mcp-customs/src/internal/harness"
)

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	if err := serve(log); err != nil {
		log.Error("The harness stopped.", "error", err.Error())
		os.Exit(1)
	}
}

func serve(log *slog.Logger) error {
	token := os.Getenv("HARNESS_TOKEN")
	// This drops the token from Go's copy of the environment, so nothing the
	// harness starts inherits it. /proc/<pid>/environ still holds it; only
	// running the server as another user keeps it out of reach.
	if err := os.Unsetenv("HARNESS_TOKEN"); err != nil {
		return err
	}
	u, err := user.Lookup(envOr("HARNESS_USER", "dev"))
	if err != nil {
		return err
	}
	account, err := accountFor(u, os.Geteuid())
	if err != nil {
		return err
	}
	eg, stopEgress, err := startEgress(context.Background(), account.UID)
	if err != nil {
		return err
	}
	defer stopEgress()
	h, err := harness.New(harness.Config{
		Token:          token,
		Account:        account,
		Workdir:        envOr("HARNESS_WORKDIR", filepath.Join(account.Home, "projects", "server")),
		WatchRoots:     []string{"/tmp", "/var/tmp", "/dev/shm"},
		Path:           envOr("PATH", "/usr/local/bin:/usr/bin:/bin"),
		Installer:      harness.Toolchain{},
		Egress:         eg,
		Now:            time.Now,
		InstallTimeout: 10 * time.Minute,
		CallTimeout:    time.Minute,
	}, log)
	if err != nil {
		return err
	}
	defer h.Close()

	srv := &http.Server{
		Addr:              ":" + envOr("PORT", "8080"),
		Handler:           h,
		ReadHeaderTimeout: 10 * time.Second,
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdown)
	}()
	log.Info("The harness is listening.", "addr", srv.Addr, "user", account.Name)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// accountFor is the unprivileged account the server under test runs as.
// The harness must run as root (euid 0) and switch to it: run as the
// harness's own user, the server could read the token from the harness's
// /proc/<pid>/environ, ptrace it and read its files. So it refuses to
// start as anyone else, and refuses an account that is root.
func accountFor(u *user.User, euid int) (harness.Account, error) {
	if euid != 0 {
		return harness.Account{}, fmt.Errorf("the harness runs as uid %d; it must run as root to run the server as %s", euid, u.Username)
	}
	uid, err := strconv.ParseUint(u.Uid, 10, 32)
	if err != nil {
		return harness.Account{}, fmt.Errorf("the uid of %s: %w", u.Username, err)
	}
	gid, err := strconv.ParseUint(u.Gid, 10, 32)
	if err != nil {
		return harness.Account{}, fmt.Errorf("the gid of %s: %w", u.Username, err)
	}
	if uid == 0 || gid == 0 {
		return harness.Account{}, fmt.Errorf("%s is root; the server must run as an unprivileged user", u.Username)
	}
	return harness.Account{
		Name:   u.Username,
		Home:   u.HomeDir,
		UID:    uint32(uid),
		GID:    uint32(gid),
		Switch: true,
	}, nil
}

// trustDir is where the server finds the proxy CA's certificate.
const trustDir = "/etc/mcp-customs"

// firewallChain names the netfilter chains of the firewall.
const firewallChain = "MCP_CUSTOMS"

// startEgress starts the egress proxy and puts up the firewall for uid. The
// stop function takes both down.
func startEgress(ctx context.Context, uid uint32) (*egress.Egress, func(), error) {
	ca, err := egress.NewCA(time.Now)
	if err != nil {
		return nil, nil, err
	}
	roots, err := egress.SystemRoots()
	if err != nil {
		return nil, nil, err
	}
	trust, err := egress.WriteTrust(trustDir, ca, roots)
	if err != nil {
		return nil, nil, err
	}
	l, err := egress.Listen(ctx)
	if err != nil {
		return nil, nil, err
	}
	eg := egress.New(egress.Config{
		CA:        ca,
		Upstream:  &http.Transport{Proxy: nil, ForceAttemptHTTP2: true, TLSHandshakeTimeout: 10 * time.Second},
		Resolver:  net.DefaultResolver,
		Allow:     egress.RegistryHosts,
		ServerEnv: egress.Env(l.Proxy.Addr().String(), trust),
	})
	stop := eg.Serve(l, egress.RedirectedFrom)
	proxy, dns, catch := l.Ports()
	fw := egress.Firewall{Chain: firewallChain, UID: uid, ProxyPort: proxy, DNSPort: dns, CatchPort: catch}
	fw.Down(ctx, runCommand) // what an earlier harness left
	if err := fw.Up(ctx, runCommand); err != nil {
		stop()
		return nil, nil, err
	}
	return eg, func() {
		fw.Down(context.Background(), runCommand)
		stop()
	}, nil
}

// runCommand runs an iptables command.
func runCommand(ctx context.Context, c egress.Command) error {
	out, err := exec.CommandContext(ctx, c[0], c[1:]...).CombinedOutput() //nolint:gosec // the firewall's own fixed commands
	if err != nil {
		return fmt.Errorf("%w: %s", err, out)
	}
	return nil
}

func envOr(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}
