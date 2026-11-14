package store

import (
	"context"
	"errors"
	"strings"
)

// ProxyPrefix is where the bucket keeps the demo Go module proxy's files
// (docs/contracts.md, "The demo proxy"). `make demo-publish` writes them;
// nothing in the stack does.
const ProxyPrefix = "goproxy/"

// ErrBadProxyPath says a path names no file of a module proxy.
var ErrBadProxyPath = errors.New("not a path of a module proxy's file")

// ProxyReader reads the demo proxy's files, under ProxyPrefix, and nothing
// else of the bucket: the web function's view of it.
type ProxyReader struct {
	client S3GetAPI
	name   string
}

// NewProxyReader returns a reader of bucket name's proxy files, through client.
func NewProxyReader(client S3GetAPI, name string) *ProxyReader {
	return &ProxyReader{client: client, name: name}
}

// GetProxyFile reads the proxy's file at path, such as
// `<module>/@v/list`, and false when there is none.
func (r *ProxyReader) GetProxyFile(ctx context.Context, path string) ([]byte, bool, error) {
	for seg := range strings.SplitSeq(path, "/") {
		if seg == "" || seg == "." || seg == ".." {
			return nil, false, ErrBadProxyPath
		}
	}
	return getBounded(ctx, r.client, r.name, ProxyPrefix+path)
}
