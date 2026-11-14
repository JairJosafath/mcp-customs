// Command harness serves the Harness API in the MicroVM: it installs and
// runs the server under test as an unprivileged user and reports what the
// server does. Wiring only; the work is in internal/harness.
//
// Lambda starts it once, at image build, and snapshots it, so it starts
// with no per-run value: Lambda's /run hook, on HOOKS_PORT, delivers the
// run's token and canaries when a MicroVM resumes (docs/contracts.md, "The
// MicroVM"). It reads HARNESS_USER (the unprivileged user, "dev" by
// default), HARNESS_WORKDIR (the server's working directory,
// ~/projects/server by default), PORT (the Harness API's, 8080 by default),
// HOOKS_PORT (9000 by default), and GO_PROXY_URL, the GOPROXY-style list
// Go installs resolve through, whose hosts an install may reach (Go's own
// default when unset). It must run as root, and refuses to
// start otherwise: it runs the server as the unprivileged user, never as
// itself.
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
	"net/url"
	"os"
	"os/signal"
	"os/user"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/JairJosafath/mcp-customs/src/internal/demoproxy"
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
	u, err := user.Lookup(envOr("HARNESS_USER", "dev"))
	if err != nil {
		return err
	}
	account, err := accountFor(u, os.Geteuid())
	if err != nil {
		return err
	}
	goProxy := os.Getenv("GO_PROXY_URL")
	proxyHosts, err := hostsOf(goProxy)
	if err != nil {
		return err
	}
	eg, stopEgress, err := startEgress(context.Background(), account, append(slices.Clone(egress.RegistryHosts), proxyHosts...))
	if err != nil {
		return err
	}
	defer stopEgress()
	cfg := configFor(account)
	cfg.GoProxy = goProxy
	cfg.Egress = eg
	h, err := harness.New(cfg, log)
	if err != nil {
		return err
	}
	defer h.Close()

	api, err := net.Listen("tcp", ":"+envOr("PORT", "8080"))
	if err != nil {
		return err
	}
	hooks, err := net.Listen("tcp", ":"+envOr("HOOKS_PORT", "9000"))
	if err != nil {
		_ = api.Close()
		return err
	}
	h.Listening()
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	log.Info("The harness is listening.", "api", api.Addr().String(), "hooks", hooks.Addr().String(), "user", account.Name)
	errs := make(chan error, 2)
	servers := []*http.Server{httpServer(h), httpServer(h.Hooks())}
	for i, ln := range []net.Listener{api, hooks} {
		go func() { errs <- servers[i].Serve(ln) }()
	}
	select {
	case <-ctx.Done():
	case err = <-errs:
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, srv := range servers {
		_ = srv.Shutdown(shutdown)
	}
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// serverPath is the PATH the server under test and its install get after
// their own commands, and the only one the harness finds its own install
// commands on: the image's toolchains and the system's, never the
// harness's own PATH (root's, with /root/.local/bin).
const serverPath = "/usr/local/bin:/usr/local/go/bin:/usr/local/node/bin:/usr/bin:/bin"

// configFor is the harness's configuration for the account: nothing of it
// per run, and the server's PATH its own, not the harness's.
func configFor(account harness.Account) harness.Config {
	return harness.Config{
		Account:        account,
		Workdir:        envOr("HARNESS_WORKDIR", filepath.Join(account.Home, "projects", "server")),
		WatchRoots:     []string{"/tmp", "/var/tmp", "/dev/shm"},
		Path:           serverPath,
		Installer:      harness.Toolchain{},
		Now:            time.Now,
		InstallTimeout: 10 * time.Minute,
		CallTimeout:    time.Minute,
	}
}

func httpServer(h http.Handler) *http.Server {
	return &http.Server{Handler: h, ReadHeaderTimeout: 10 * time.Second}
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

// trustOutside refuses a trust directory inside the account's home, where
// the server under test could replace what the harness writes.
func trustOutside(dir, home string) error {
	rel, err := filepath.Rel(filepath.Clean(home), filepath.Clean(dir))
	if err != nil || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))) {
		return fmt.Errorf("the proxy's trust directory %s is inside %s, the server's home", dir, home)
	}
	return nil
}

// firewallChain names the netfilter chains of the firewall.
const firewallChain = "MCP_CUSTOMS"

// nflogGroup is the NFLOG group the firewall logs refused packets to.
const nflogGroup = 47

// hostsOf is the hosts of list, a GOPROXY-style list (GO_PROXY_URL, which
// the stack sets to its demo proxy and the public one): an install may
// reach them. An empty list has none.
func hostsOf(list string) ([]string, error) {
	if list == "" {
		return nil, nil
	}
	urls, err := demoproxy.SplitProxyList(list)
	if err != nil {
		return nil, fmt.Errorf("GO_PROXY_URL: %w", err)
	}
	hosts := make([]string, 0, len(urls))
	for _, u := range urls {
		parsed, err := url.Parse(u)
		if err != nil {
			return nil, fmt.Errorf("GO_PROXY_URL: %w", err)
		}
		hosts = append(hosts, parsed.Hostname())
	}
	return hosts, nil
}

// startEgress starts the egress proxy and puts up the firewall for uid,
// allowing installAllow while an install runs. The stop function takes
// both down.
func startEgress(ctx context.Context, account harness.Account, installAllow []string) (*egress.Egress, func(), error) {
	if err := trustOutside(trustDir, account.Home); err != nil {
		return nil, nil, err
	}
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
		CA:           ca,
		Upstream:     &http.Transport{Proxy: nil, ForceAttemptHTTP2: true, TLSHandshakeTimeout: 10 * time.Second},
		Resolver:     net.DefaultResolver,
		InstallAllow: installAllow,
		ServerEnv:    egress.Env(l.Proxy.Addr().String(), trust),
	})
	nflog, err := egress.OpenNFLog(nflogGroup)
	if err != nil {
		return nil, nil, err
	}
	logged := make(chan struct{})
	go func() {
		defer close(logged)
		_ = eg.ServeNFLog(nflog)
	}()
	serving := eg.Serve(l, egress.RedirectedFrom)
	stop := func() {
		serving()
		_ = nflog.Close()
		<-logged
	}
	proxy, dns, catch := l.Ports()
	fw := egress.Firewall{Chain: firewallChain, UID: account.UID, ProxyPort: proxy, DNSPort: dns, CatchPort: catch, NFLogGroup: nflogGroup}
	fw.Down(ctx, egress.Exec) // what an earlier harness left
	if err := fw.Up(ctx, egress.Exec); err != nil {
		stop()
		return nil, nil, err
	}
	return eg, func() {
		fw.Down(context.Background(), egress.Exec)
		stop()
	}, nil
}

func envOr(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}
