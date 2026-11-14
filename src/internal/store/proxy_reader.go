package store

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/aws/smithy-go"
)

// ProxyPrefix is where the bucket keeps the demo Go module proxy's files
// (docs/contracts.md, "The demo proxy"). The deploy writes them;
// nothing the stack runs does.
const ProxyPrefix = "goproxy/"

// ErrProxyDenied says S3 denied the read of a proxy file. Without
// s3:ListBucket, S3 answers a missing key so; with it, only a policy that
// is wrong does. Either way the proxy has no such file to serve.
var ErrProxyDenied = errors.New("S3 denied the read of the proxy file")

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
// `<module>/@v/list`, and false when there is none. A read S3 denies is
// ErrProxyDenied, which the caller answers as no file.
func (r *ProxyReader) GetProxyFile(ctx context.Context, path string) ([]byte, bool, error) {
	for seg := range strings.SplitSeq(path, "/") {
		if seg == "" || seg == "." || seg == ".." {
			return nil, false, ErrBadProxyPath
		}
	}
	body, found, err := getBounded(ctx, r.client, r.name, ProxyPrefix+path)
	if apiErr := smithy.APIError(nil); errors.As(err, &apiErr) && apiErr.ErrorCode() == "AccessDenied" {
		return nil, false, fmt.Errorf("%s: %w", ProxyPrefix+path, ErrProxyDenied)
	}
	return body, found, err
}
