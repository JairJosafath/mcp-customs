package harness

import (
	"errors"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"syscall"
)

// maxSource bounds the content /source answers.
const maxSource = 64 << 10

type pathRequest struct {
	Path string `json:"path"`
}

// source answers one file of the installed package, by a path relative to
// it. A path that leaves the package, or a link out of it, is refused.
func (h *Harness) source(r *http.Request) (int, answer) {
	var req pathRequest
	if err := decode(r, &req); err != nil {
		return problem(http.StatusBadRequest, err.Error())
	}
	p := req.Path
	if p == "" || filepath.IsAbs(p) || filepath.Clean(p) != p || p == ".." || strings.HasPrefix(p, "../") {
		return problem(http.StatusBadRequest, "The path is relative to the installed package, clean, and inside it.")
	}
	if h.run == nil || h.run.source == "" {
		return problem(http.StatusConflict, "No package is installed to read.")
	}
	root, err := openRoot(h.cfg.Account.Home, h.run.source)
	if err != nil {
		return problem(http.StatusBadRequest, "The installed package can't be read: "+err.Error())
	}
	defer func() { _ = root.Close() }()
	f, info, err := h.cfg.Account.openOwned(root, p, true)
	if errors.Is(err, errNotFound) {
		return problem(http.StatusNotFound, "The package has no file "+p+".")
	}
	if err != nil {
		return problem(http.StatusBadRequest, err.Error())
	}
	defer func() { _ = f.Close() }()
	// A hard link may be a file from outside the package.
	if st, ok := info.Sys().(*syscall.Stat_t); !ok || st.Nlink != 1 {
		return problem(http.StatusBadRequest, p+" is a hard link, which may lead out of the package.")
	}
	content, err := io.ReadAll(io.LimitReader(f, maxSource+1))
	if err != nil {
		return problem(http.StatusInternalServerError, "Could not read "+p+": "+err.Error())
	}
	truncated := len(content) > maxSource
	if truncated {
		content = content[:maxSource]
	}
	return http.StatusOK, answer{"path": p, "content": strings.ToValidUTF8(string(content), "�"), "truncated": truncated}
}
