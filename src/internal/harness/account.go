package harness

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
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

// setpriv is util-linux's setpriv, which the image ships (sandbox/Dockerfile).
const setpriv = "/usr/bin/setpriv"

// waitDelay is how long a stopped command's pipes may stay open before
// they are closed for it.
const waitDelay = 2 * time.Second

// command is args run as the account in dir, with exactly env: nothing of
// the harness's own environment reaches it. It is its own process group,
// so cancelling ctx kills whatever it started. Switched to the account, it
// starts through setpriv --no-new-privs, so nothing it runs can gain
// privileges, and setpriv finds args[0] on env's PATH, not the harness's.
func (a Account) command(ctx context.Context, dir string, env, args []string) *exec.Cmd {
	if a.Switch {
		args = append([]string{setpriv, "--no-new-privs", "--"}, args...)
	}
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

// resolve is args with a bare command name replaced by its absolute path
// on path, as the harness's own PATH finds it. A name with a slash is kept.
// setpriv would otherwise look the name up on the command's environment,
// which the server under test can write to.
func resolve(args []string, path string) ([]string, error) {
	if len(args) == 0 {
		return nil, errors.New("no command to run")
	}
	if strings.Contains(args[0], "/") {
		return args, nil
	}
	for _, dir := range filepath.SplitList(path) {
		if !filepath.IsAbs(dir) {
			continue
		}
		file := filepath.Join(dir, args[0])
		if info, err := os.Stat(file); err == nil && info.Mode().IsRegular() && info.Mode().Perm()&0o111 != 0 {
			return append([]string{file}, args[1:]...), nil
		}
	}
	return nil, fmt.Errorf("%s is not on the harness's PATH", args[0])
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

// killAll kills every process of the account: a shell switched to it sends
// SIGKILL to -1, which reaches every process the account may signal, those
// that left their process group or session included, and not the shell
// itself. Without Switch the account is the harness's own user, whose
// processes are the harness's: then nothing is killed.
func (a Account) killAll(ctx context.Context) error {
	if !a.Switch {
		return nil
	}
	// kill fails only when nothing was left to kill.
	return a.run(ctx, "/", a.env("/usr/bin:/bin"), []string{"/bin/sh", "-c", "kill -KILL -1 2>/dev/null; exit 0"}, io.Discard)
}
