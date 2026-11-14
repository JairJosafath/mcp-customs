package harness

import (
	"errors"
	"io/fs"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// maxWatchedFiles bounds one snapshot, so a server that makes millions of
// files can't stall the harness. Files past it go unseen, which the watch
// says. The planted home holds a few dozen files and the demo servers
// write a handful outside their working directory, whose caches the watch
// skips.
const maxWatchedFiles = 200_000

var errEnough = errors.New("enough files")

type fileState struct {
	mod  time.Time
	size int64
	mode fs.FileMode
}

// watcher finds the files created or changed under its roots, outside the
// server's working directory, between two looks. It compares snapshots, so
// a file written and removed between looks goes unseen.
type watcher struct {
	roots []string
	skip  string
	last  map[string]fileState
	// max is the most files a snapshot holds: maxWatchedFiles.
	max int
	// truncated says a snapshot stopped at max.
	truncated bool
}

func newWatcher(roots []string, skip string) *watcher {
	w := &watcher{roots: roots, skip: filepath.Clean(skip), max: maxWatchedFiles}
	w.last = w.snapshot()
	return w
}

func (w *watcher) snapshot() map[string]fileState {
	seen := map[string]fileState{}
	for _, root := range w.roots {
		err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil //nolint:nilerr // a directory the harness can't read is skipped, not fatal
			}
			if w.skipped(path) {
				return filepath.SkipDir
			}
			if d.IsDir() {
				return nil
			}
			info, err := d.Info()
			if err != nil {
				return nil //nolint:nilerr // the file went away during the walk
			}
			seen[path] = fileState{mod: info.ModTime(), size: info.Size(), mode: info.Mode()}
			if len(seen) >= w.max {
				w.truncated = true
				return errEnough
			}
			return nil
		})
		if errors.Is(err, errEnough) {
			break
		}
	}
	return seen
}

func (w *watcher) skipped(path string) bool {
	return path == w.skip || strings.HasPrefix(path, w.skip+string(filepath.Separator))
}

// changes returns the files created or changed since the last look, by path.
func (w *watcher) changes() []FileDetail {
	now := w.snapshot()
	var out []FileDetail
	for path, st := range now {
		before, ok := w.last[path]
		switch {
		case !ok:
			out = append(out, FileDetail{Path: path, Change: "created"})
		case !before.mod.Equal(st.mod) || before.size != st.size || before.mode != st.mode:
			out = append(out, FileDetail{Path: path, Change: "modified"})
		}
	}
	w.last = now
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}
