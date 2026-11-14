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
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

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
	h, err := harness.New(harness.Config{
		Token:          token,
		Account:        account,
		Workdir:        envOr("HARNESS_WORKDIR", filepath.Join(account.Home, "projects", "server")),
		WatchRoots:     []string{"/tmp", "/var/tmp", "/dev/shm"},
		Path:           envOr("PATH", "/usr/local/bin:/usr/bin:/bin"),
		Installer:      harness.Toolchain{},
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

func envOr(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}
