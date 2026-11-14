package harness

import (
	"os"
	"runtime"
	"syscall"
	"unsafe"
)

// asAccount runs do on an OS thread whose file-system identity is the
// account's: its fsuid, its fsgid and no supplementary groups, with no
// capabilities left. The kernel then checks each permission the path
// lookups do make, search on each directory included, as the account, at
// the moment it resolves them, so a rename between a check and an open
// can't widen what's reached. It doesn't make the thread the account: it
// stays in the harness's thread group, where /proc's magic links skip those
// checks, so do must resolve paths with openNoMagic. The thread is never
// handed back: do runs on a locked goroutine that exits locked, so Go ends
// the thread with it.
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

// becomeFS sets this thread's file-system identity to the account's and
// drops its capabilities, and says whether it took. Raw system calls
// change one thread, not the whole process as Go's wrappers do.
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
	return gid == uintptr(a.GID) && uid == uintptr(a.UID) && dropCapabilities()
}

// dropCapabilities empties this thread's capability sets, so nothing,
// CAP_SYS_PTRACE included, lets it reach past the account's permissions.
func dropCapabilities() bool {
	header := struct {
		version uint32
		pid     int32
	}{version: 0x20080522} // _LINUX_CAPABILITY_VERSION_3; pid 0 is this thread
	var data [2]struct{ effective, permitted, inheritable uint32 }
	_, _, errno := syscall.RawSyscall(syscall.SYS_CAPSET,
		uintptr(unsafe.Pointer(&header)), uintptr(unsafe.Pointer(&data)), 0) //nolint:gosec // capset(2) takes these two structs
	return errno == 0
}

// The parts of openat2(2) syscall lacks; its number is the same on amd64
// and arm64.
const (
	sysOpenat2          = 437
	atFDCWD             = ^uintptr(99) // AT_FDCWD, -100
	oPath               = 0o10000000
	resolveNoMagiclinks = 0x02
)

// openNoMagic opens name as open(2) would, except that it refuses any path
// that passes through a /proc magic link, such as /proc/self/fd/N or
// /proc/self/cwd: those reach a file without the lookup ever checking the
// directories above it.
func openNoMagic(name string, flags int) (*os.File, error) {
	path, err := syscall.BytePtrFromString(name)
	if err != nil {
		return nil, err
	}
	how := struct{ flags, mode, resolve uint64 }{
		flags:   uint64(flags | syscall.O_CLOEXEC), //nolint:gosec // open flags are never negative
		resolve: resolveNoMagiclinks,
	}
	fd, _, errno := syscall.Syscall6(sysOpenat2, atFDCWD,
		uintptr(unsafe.Pointer(path)), uintptr(unsafe.Pointer(&how)), unsafe.Sizeof(how), 0, 0) //nolint:gosec // openat2(2) takes a path and an open_how
	if errno != 0 {
		return nil, errno
	}
	return os.NewFile(fd, name), nil
}
