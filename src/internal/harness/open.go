package harness

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

// errNotFound is a file that isn't there; every other open failure is the
// caller's bad path.
var errNotFound = errors.New("no such file")

// openRoot opens dir as a root no path read in it can leave, refusing a
// dir reached through a link: dir must be under base, whose path the
// harness trusts, and the directory opened must be at dir's real path.
// The check is on the opened directory itself, so a link swapped in after
// it changes nothing.
func openRoot(base, dir string) (*os.Root, error) {
	rel, err := filepath.Rel(base, dir)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return nil, fmt.Errorf("%s is not under %s", dir, base)
	}
	realBase, err := filepath.EvalSymlinks(base)
	if err != nil {
		return nil, fmt.Errorf("find %s: %w", base, err)
	}
	b, err := os.OpenRoot(realBase)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", base, err)
	}
	defer func() { _ = b.Close() }()
	root, err := b.OpenRoot(rel)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", dir, err)
	}
	here, err := root.Open(".")
	if err != nil {
		_ = root.Close()
		return nil, fmt.Errorf("open %s: %w", dir, err)
	}
	at, err := os.Readlink("/proc/self/fd/" + strconv.FormatUint(uint64(here.Fd()), 10))
	_ = here.Close()
	if err != nil || at != filepath.Join(realBase, rel) {
		_ = root.Close()
		return nil, fmt.Errorf("%s is reached through a link", dir)
	}
	return root, nil
}

// afterLook, when set, runs between openOwned's look at a name and its
// open: tests swap the file there, to show the swap is refused.
var afterLook func(name string)

// openOwned opens name in root for reading: a regular file only, so no
// FIFO or device can stall the harness; never a hard link, which may be a
// file from anywhere; and, when the harness switches to the account, one
// the account owns. With follow false a link as the last element is refused:
// os.Root follows a link that stays inside it even with O_NOFOLLOW, so the
// element is looked at first, and the file opened must be the one seen.
func (a Account) openOwned(root *os.Root, name string, follow bool) (*os.File, fs.FileInfo, error) {
	var seen fs.FileInfo
	if !follow {
		var err error
		if seen, err = root.Lstat(name); errors.Is(err, fs.ErrNotExist) {
			return nil, nil, errNotFound
		} else if err != nil {
			return nil, nil, fmt.Errorf("%s can't be read here: %w", name, err)
		}
		if seen.Mode()&fs.ModeSymlink != 0 {
			return nil, nil, fmt.Errorf("%s is a link", name)
		}
		if afterLook != nil {
			afterLook(name)
		}
	}
	f, err := root.OpenFile(name, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil, errNotFound
	}
	if err != nil {
		return nil, nil, fmt.Errorf("%s can't be read here: %w", name, err)
	}
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		_ = f.Close()
		return nil, nil, fmt.Errorf("%s is not a regular file", name)
	}
	if seen != nil && !os.SameFile(seen, info) {
		_ = f.Close()
		return nil, nil, fmt.Errorf("%s changed while it was opened", name)
	}
	if st, ok := info.Sys().(*syscall.Stat_t); !ok || st.Nlink != 1 {
		_ = f.Close()
		return nil, nil, fmt.Errorf("%s is a hard link, which may be a file from anywhere", name)
	}
	if st, ok := info.Sys().(*syscall.Stat_t); a.Switch && (!ok || st.Uid != a.UID) {
		_ = f.Close()
		return nil, nil, fmt.Errorf("%s is not the account's own file", name)
	}
	return f, info, nil
}
