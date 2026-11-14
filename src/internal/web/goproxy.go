package web

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
)

// GoProxy reads the demo Go module proxy's files, and false for a file it
// doesn't have.
type GoProxy interface {
	GetProxyFile(ctx context.Context, path string) ([]byte, bool, error)
}

// proxyPath is a file of the module proxy protocol, module path and version
// escaped: `<module>/@v/list`, `@v/<version>.info`, `.mod`, `.zip`, or
// `<module>/@latest`.
var proxyPath = regexp.MustCompile(`^[a-z0-9.!_~-]+(/[a-z0-9.!_~-]+)*/@(latest|v/list|v/[a-z0-9.!+_-]+\.(info|mod|zip))$`)

// proxyTypes are the content types of the proxy's files, by what the path ends in.
var proxyTypes = []struct{ suffix, contentType string }{
	{"/@v/list", "text/plain; charset=utf-8"},
	{"/@latest", "application/json"},
	{".info", "application/json"},
	{".mod", "text/plain; charset=utf-8"},
	{".zip", "application/zip"},
}

// proxyFilePath is path unescaped, and false when it names no file of the
// protocol or steps out of its directory.
func proxyFilePath(path string) (string, bool) {
	p, err := url.PathUnescape(path)
	if err != nil {
		return "", false
	}
	segments := strings.Split(p, "/")
	return p, proxyPath.MatchString(p) && !slices.Contains(segments, "..") && !slices.Contains(segments, ".")
}

// goProxyFile answers the demo proxy's file at path, the request's path
// after /goproxy/. Anything else is 404, which tells the go command to ask
// the next proxy on its list.
func (h *Handler) goProxyFile(ctx context.Context, path string) (Response, error) {
	p, ok := proxyFilePath(path)
	if !ok {
		return problem(http.StatusNotFound, "No module proxy file "+quotable(path)+"."), nil
	}
	body, found, err := h.deps.Proxy.GetProxyFile(ctx, p)
	if err != nil {
		return Response{}, fmt.Errorf("read the proxy file %s: %w", p, err)
	}
	if !found {
		return problem(http.StatusNotFound, "No module proxy file "+quotable(path)+"."), nil
	}
	contentType := "application/octet-stream"
	for _, t := range proxyTypes {
		if strings.HasSuffix(p, t.suffix) {
			contentType = t.contentType
			break
		}
	}
	return Response{
		StatusCode:      http.StatusOK,
		Headers:         map[string]string{"content-type": contentType},
		Body:            base64.StdEncoding.EncodeToString(body),
		IsBase64Encoded: true,
	}, nil
}
