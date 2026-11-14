package harness

import (
	"slices"
	"testing"
)

func TestAccountCommandsRunAsTheUnprivilegedUser(t *testing.T) {
	a := Account{Name: "dev", Home: "/home/dev", UID: 1000, GID: 1001, Switch: true}
	cmd := a.command(t.Context(), "/home/dev/projects/server", a.env("/usr/bin"), []string{"/usr/bin/true"})
	cred := cmd.SysProcAttr.Credential
	if cred == nil || cred.Uid != 1000 || cred.Gid != 1001 || len(cred.Groups) != 0 {
		t.Errorf("credential = %+v, want uid 1000, gid 1001 and no other groups", cred)
	}
	if !cmd.SysProcAttr.Setpgid {
		t.Error("the command is not its own process group, so it can't be killed whole")
	}
	if cmd.Dir != "/home/dev/projects/server" {
		t.Errorf("dir = %s", cmd.Dir)
	}
	want := []string{
		"HOME=/home/dev", "USER=dev", "LOGNAME=dev", "SHELL=/bin/bash",
		"LANG=en_US.UTF-8", "TERM=xterm-256color", "PATH=/usr/bin",
	}
	if !slices.Equal(cmd.Env, want) {
		t.Errorf("env = %q, want exactly %q", cmd.Env, want)
	}
}

func TestAccountWithoutSwitchRunsAsTheHarnessUser(t *testing.T) {
	a := Account{Name: "dev", Home: t.TempDir()}
	if cred := a.sysProcAttr().Credential; cred != nil {
		t.Errorf("credential = %+v, want none", cred)
	}
}
