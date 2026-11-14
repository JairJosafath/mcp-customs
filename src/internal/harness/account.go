package harness

import (
	"context"
	"errors"
	"io"
	"os/exec"
	"syscall"
	"time"
)

// An Account is the unprivileged user the server under test, and its
// install, run as. Its home holds the fake developer setup.
type Account struct {
	Name string
	Home string
	UID  uint32
	GID  uint32
	// Switch makes commands run as UID and GID. It needs the harness to run
	// as root; without it commands run as the harness's own user, as in tests.
	Switch bool
}

// waitDelay is how long a stopped command's pipes may stay open before
// they are closed for it.
const waitDelay = 2 * time.Second

// command is args run as the account in dir, with exactly env: nothing of
// the harness's own environment reaches it. It is its own process group,
// so cancelling ctx kills whatever it started.
func (a Account) command(ctx context.Context, dir string, env, args []string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, args[0], args[1:]...) //nolint:gosec // running the server under test, and its install, is the harness's job; it runs as the unprivileged account
	cmd.Dir = dir
	cmd.Env = env
	cmd.SysProcAttr = a.sysProcAttr()
	cmd.Cancel = func() error { return killGroup(cmd) }
	cmd.WaitDelay = waitDelay
	return cmd
}

func (a Account) sysProcAttr() *syscall.SysProcAttr {
	attr := &syscall.SysProcAttr{Setpgid: true}
	if a.Switch {
		attr.Credential = &syscall.Credential{Uid: a.UID, Gid: a.GID, Groups: []uint32{}}
	}
	return attr
}

// env is the whole environment a command of the account gets: a
// developer's shell, built from nothing, so no AWS_*, LAMBDA_* or harness
// variable can leak into it.
func (a Account) env(path string, extra ...string) []string {
	return append([]string{
		"HOME=" + a.Home,
		"USER=" + a.Name,
		"LOGNAME=" + a.Name,
		"SHELL=/bin/bash",
		"LANG=en_US.UTF-8",
		"TERM=xterm-256color",
		"PATH=" + path,
	}, extra...)
}

// run runs args as the account to the end, writing its output to out.
func (a Account) run(ctx context.Context, dir string, env, args []string, out io.Writer) error {
	if len(args) == 0 {
		return errors.New("no command to run")
	}
	cmd := a.command(ctx, dir, env, args)
	cmd.Stdout, cmd.Stderr = out, out
	return cmd.Run()
}

// killGroup kills cmd's process group: the command and all it started.
func killGroup(cmd *exec.Cmd) error {
	if cmd.Process == nil {
		return nil
	}
	if err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL); err != nil && !errors.Is(err, syscall.ESRCH) {
		return err
	}
	return nil
}
