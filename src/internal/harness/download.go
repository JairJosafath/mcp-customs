package harness

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"strings"
)

// The bounds of /download: the file it hashes, and the excerpt it answers.
const (
	maxDownload        = 256 << 20
	maxDownloadExcerpt = 4 << 10
)

// download describes a file the server wrote, one seen as a file
// observation: its size, SHA-256, kind and the start of its content.
func (h *Harness) download(r *http.Request) (int, answer) {
	var req pathRequest
	if err := decode(r, &req); err != nil {
		return problem(http.StatusBadRequest, err.Error())
	}
	p := req.Path
	if !filepath.IsAbs(p) || filepath.Clean(p) != p {
		return problem(http.StatusBadRequest, "The path is absolute and clean.")
	}
	h.noteFiles()
	if h.run == nil || !h.run.written[p] {
		return problem(http.StatusNotFound, "The server was not seen writing "+p+".")
	}
	base, rel, ok := h.watchRootOf(p)
	if !ok {
		return problem(http.StatusBadRequest, p+" is not where written files are watched.")
	}
	root, err := openRoot(base, base)
	if err != nil {
		return problem(http.StatusInternalServerError, "Could not open "+base+": "+err.Error())
	}
	defer func() { _ = root.Close() }()
	f, info, err := h.cfg.Account.openOwned(root, rel, false)
	if errors.Is(err, errNotFound) {
		return problem(http.StatusNotFound, p+" is gone.")
	}
	if err != nil {
		return problem(http.StatusBadRequest, err.Error())
	}
	defer func() { _ = f.Close() }()
	if info.Size() > maxDownload {
		return problem(http.StatusRequestEntityTooLarge, fmt.Sprintf("%s is %d bytes; at most %d are hashed.", p, info.Size(), maxDownload))
	}
	head := make([]byte, maxDownloadExcerpt)
	n, err := io.ReadFull(f, head)
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
		return problem(http.StatusInternalServerError, "Could not read "+p+": "+err.Error())
	}
	head = head[:n]
	sum := sha256.New()
	sum.Write(head)
	rest, err := io.Copy(sum, io.LimitReader(f, maxDownload))
	if err != nil {
		return problem(http.StatusInternalServerError, "Could not read "+p+": "+err.Error())
	}
	return http.StatusOK, answer{
		"path":    p,
		"size":    int64(n) + rest,
		"sha256":  hex.EncodeToString(sum.Sum(nil)),
		"kind":    http.DetectContentType(head),
		"excerpt": strings.ToValidUTF8(string(head), "�"),
	}
}

// watchRootOf is the watched directory p is in, and p relative to it.
func (h *Harness) watchRootOf(p string) (root, rel string, ok bool) {
	for _, dir := range append([]string{h.cfg.Account.Home}, h.cfg.WatchRoots...) {
		dir = filepath.Clean(dir)
		if rest, in := strings.CutPrefix(p, dir+string(filepath.Separator)); in && rest != "" {
			return dir, rest, true
		}
	}
	return "", "", false
}
