package harness

import (
	"bufio"
	"debug/buildinfo"
	"debug/elf"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
)

// Whether the server's runtime sees a /clock move.
const (
	appliesYes     = "yes"
	appliesNo      = "no"
	appliesUnknown = "unknown"
)

// maxShebang bounds the first line read of a script.
const maxShebang = 256

// fakeTimeApplies says whether libfaketime, preloaded, can move the clock
// command sees, and why. It can't for a static binary, which loads nothing,
// nor for a Go binary, which asks the kernel for the time without libc. A
// script is judged by its interpreter, found on path as the shell would.
// It is advice for the judge, not a control: a server can still clear its
// own environment, or set its clock itself.
//
// The command is the server's to point anywhere, so only a file the
// account could read itself is read, and why names nothing read from a
// file: only the command's own base name.
func (a Account) fakeTimeApplies(command []string, path string) (applies, why string) {
	if len(command) == 0 || command[0] == "" {
		return appliesUnknown, "no server command is known yet"
	}
	name := filepath.Base(command[0])
	exe := command[0]
	for range 2 {
		interp, ok := a.shebang(exe)
		if !ok {
			break
		}
		if filepath.Base(interp[0]) == "env" && len(interp) > 1 {
			interp = interp[1:]
		}
		found, ok := a.interpreter(interp[0], path)
		if !ok {
			return appliesUnknown, "the interpreter of " + name + " was not found"
		}
		exe = found
	}
	return a.elfApplies(exe, name)
}

// interpreterName is the shape of an interpreter's bare name.
var interpreterName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]*$`)

// interpreter is the file a script's interpreter names: an absolute path
// as it is, a bare name found on path.
func (a Account) interpreter(name, path string) (string, bool) {
	if filepath.IsAbs(name) {
		return filepath.Clean(name), true
	}
	if !interpreterName.MatchString(name) {
		return "", false
	}
	for _, dir := range filepath.SplitList(path) {
		file := filepath.Join(dir, name)
		if filepath.IsAbs(dir) && a.isExecutable(file) {
			return file, true
		}
	}
	return "", false
}

func (a Account) isExecutable(file string) bool {
	f, err := a.openReadable(file)
	if err != nil {
		return false
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	return err == nil && info.Mode().Perm()&0o111 != 0
}

// shebang is the interpreter and its arguments a script names, if exe is one.
func (a Account) shebang(exe string) ([]string, bool) {
	f, err := a.openReadable(exe)
	if err != nil {
		return nil, false
	}
	defer func() { _ = f.Close() }()
	line, err := bufio.NewReaderSize(f, maxShebang).Peek(maxShebang)
	if err != nil && len(line) < 2 {
		return nil, false
	}
	rest, ok := strings.CutPrefix(string(line), "#!")
	if !ok {
		return nil, false
	}
	first, _, _ := strings.Cut(rest, "\n")
	fields := strings.Fields(first)
	return fields, len(fields) > 0
}

// elfApplies judges the binary exe; name is what why calls it.
func (a Account) elfApplies(exe, name string) (applies, why string) {
	f, err := a.openReadable(exe)
	if err != nil {
		return appliesUnknown, name + " can't be read as the account"
	}
	defer func() { _ = f.Close() }()
	bin, err := elf.NewFile(f)
	if err != nil {
		return appliesUnknown, name + " is neither an ELF binary nor a script that runs one"
	}
	if _, err := buildinfo.Read(f); err == nil {
		return appliesNo, name + " runs a Go binary, which reads the time without libc"
	}
	for _, p := range bin.Progs {
		if p.Type == elf.PT_INTERP {
			return appliesYes, name + " runs a dynamically linked binary, which loads libfaketime"
		}
	}
	return appliesNo, name + " runs a statically linked binary, which loads nothing"
}

// errUnreadable is a file the account couldn't read itself.
var errUnreadable = errors.New("not a regular file the account can read")

// openReadable opens, as the root harness, only what the account could
// read itself: a regular file it owns or anyone may read, along a path it
// may search and through no /proc magic link. The look and the open run
// as the account (asAccount), each through openNoMagic. It
// looks before it opens, so no device or FIFO is ever opened, and the file
// opened must be the one it looked at.
func (a Account) openReadable(name string) (*os.File, error) {
	var f *os.File
	a.asAccount(func() { f = a.openLooked(name) })
	if f == nil {
		return nil, errUnreadable
	}
	return f, nil
}

func (a Account) openLooked(name string) *os.File {
	look, err := openNoMagic(name, oPath) // an O_PATH open only looks: it opens no device
	if err != nil {
		return nil
	}
	seen, err := look.Stat()
	_ = look.Close()
	if err != nil || !a.mayRead(seen) {
		return nil
	}
	f, err := openNoMagic(name, os.O_RDONLY|syscall.O_NONBLOCK)
	if err != nil {
		return nil
	}
	if info, err := f.Stat(); err != nil || !os.SameFile(seen, info) || !a.mayRead(info) {
		_ = f.Close()
		return nil
	}
	return f
}

func (a Account) mayRead(info os.FileInfo) bool {
	st, ok := info.Sys().(*syscall.Stat_t)
	return ok && info.Mode().IsRegular() && (st.Uid == a.UID || info.Mode().Perm()&0o004 != 0)
}
