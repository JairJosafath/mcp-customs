package harness

import (
	"bufio"
	"debug/buildinfo"
	"debug/elf"
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
func fakeTimeApplies(command []string, path string) (applies, why string) {
	if len(command) == 0 || command[0] == "" {
		return appliesUnknown, "no server command is known yet"
	}
	exe := command[0]
	for range 2 {
		interp, ok := shebang(exe)
		if !ok {
			break
		}
		if filepath.Base(interp[0]) == "env" && len(interp) > 1 {
			interp = interp[1:]
		}
		found, ok := interpreter(interp[0], path)
		if !ok {
			return appliesUnknown, "the script's interpreter was not found"
		}
		exe = found
	}
	return elfApplies(exe)
}

// interpreterName is the shape of an interpreter's bare name.
var interpreterName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]*$`)

// interpreter is the file a script's interpreter names: an absolute path
// as it is, a bare name found on path.
func interpreter(name, path string) (string, bool) {
	if filepath.IsAbs(name) {
		return filepath.Clean(name), true
	}
	if !interpreterName.MatchString(name) {
		return "", false
	}
	for _, dir := range filepath.SplitList(path) {
		file := filepath.Join(dir, name)
		if filepath.IsAbs(dir) && isExecutable(file) {
			return file, true
		}
	}
	return "", false
}

func isExecutable(file string) bool {
	f, err := openRegular(file)
	if err != nil {
		return false
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	return err == nil && info.Mode().Perm()&0o111 != 0
}

// shebang is the interpreter and its arguments a script names, if exe is one.
func shebang(exe string) ([]string, bool) {
	f, err := openRegular(exe)
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

func elfApplies(exe string) (applies, why string) {
	f, err := openRegular(exe)
	if err != nil {
		return appliesUnknown, filepath.Base(exe) + " can't be read"
	}
	defer func() { _ = f.Close() }()
	bin, err := elf.NewFile(f)
	if err != nil {
		return appliesUnknown, filepath.Base(exe) + " is not an ELF binary"
	}
	if _, err := buildinfo.Read(f); err == nil {
		return appliesNo, filepath.Base(exe) + " is a Go binary, which reads the time without libc"
	}
	for _, p := range bin.Progs {
		if p.Type == elf.PT_INTERP {
			return appliesYes, filepath.Base(exe) + " is dynamically linked and loads libfaketime"
		}
	}
	return appliesNo, filepath.Base(exe) + " is statically linked and loads nothing"
}

// openRegular opens a regular file for reading, so no FIFO can stall the
// harness.
func openRegular(name string) (*os.File, error) {
	f, err := os.OpenFile(name, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	if info, err := f.Stat(); err != nil || !info.Mode().IsRegular() {
		_ = f.Close()
		return nil, syscall.EINVAL
	}
	return f, nil
}
