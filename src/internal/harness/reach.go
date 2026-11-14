package harness

import (
	"os"
	"runtime"
	"syscall"
)

// asAccount runs do on an OS thread whose file-system identity is the
// account's: its fsuid, its fsgid and no supplementary groups. The kernel
// then checks every open and stat do makes as it would for the account,
// search permission on each directory of the path included, at the moment
// it resolves it, so a rename between a check and an open can't widen
// what's reached. The thread is never handed back: do runs on a locked
// goroutine that exits locked, so Go ends the thread with it.
//
// Run by a harness that isn't root, which can't change identity, do runs
// as the harness, whose own reach is then the account's (see Switch).
func (a Account) asAccount(do func()) {
	done := make(chan struct{})
	go func() {
		defer close(done)
		runtime.LockOSThread() // never unlocked: the thread ends with the goroutine
		if os.Geteuid() == 0 && !a.becomeFS() {
			return
		}
		do()
	}()
	<-done
}

// becomeFS sets this thread's file-system identity to the account's, and
// says whether it took. Raw system calls change one thread, not the whole
// process as Go's wrappers do. fsuid away from 0 drops the capabilities
// that would bypass file permissions.
func (a Account) becomeFS() bool {
	if _, _, errno := syscall.RawSyscall(syscall.SYS_SETGROUPS, 0, 0, 0); errno != 0 {
		return false
	}
	_, _, _ = syscall.RawSyscall(syscall.SYS_SETFSGID, uintptr(a.GID), 0, 0)
	_, _, _ = syscall.RawSyscall(syscall.SYS_SETFSUID, uintptr(a.UID), 0, 0)
	// Each returns the identity before, so asking for an impossible one
	// reads back the current.
	gid, _, _ := syscall.RawSyscall(syscall.SYS_SETFSGID, ^uintptr(0), 0, 0)
	uid, _, _ := syscall.RawSyscall(syscall.SYS_SETFSUID, ^uintptr(0), 0, 0)
	return gid == uintptr(a.GID) && uid == uintptr(a.UID)
}
