package store

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
)

// S3GetAPI is the part of S3's client a ReportReader calls, so a test
// passes a fake without the network.
type S3GetAPI interface {
	GetObject(ctx context.Context, in *s3.GetObjectInput, opts ...func(*s3.Options)) (*s3.GetObjectOutput, error)
}

// MaxReportBytes bounds a report a ReportReader reads: well under the 6 MB
// a Lambda function may answer.
const MaxReportBytes = 4 << 20

// ErrReportTooLarge says a report is larger than MaxReportBytes.
var ErrReportTooLarge = fmt.Errorf("a report is larger than %d bytes", MaxReportBytes)

// ReportReader reads each check's report, reports/<check-id>.json, and
// nothing else of the bucket: the web function's view of it.
type ReportReader struct {
	client S3GetAPI
	name   string
}

// NewReportReader returns a reader of bucket name's reports, through client.
func NewReportReader(client S3GetAPI, name string) *ReportReader {
	return &ReportReader{client: client, name: name}
}

// GetReport reads check checkID's report, and false when it has none yet.
func (r *ReportReader) GetReport(ctx context.Context, checkID string) ([]byte, bool, error) {
	if !ValidCheckID(checkID) {
		return nil, false, ErrBadCheckID
	}
	return getBounded(ctx, r.client, r.name, "reports/"+checkID+".json")
}

// getBounded reads key from bucket, at most MaxReportBytes, and false when
// there is no such key.
func getBounded(ctx context.Context, client S3GetAPI, bucket, key string) ([]byte, bool, error) {
	out, err := client.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(bucket), Key: aws.String(key)})
	if noKey := new(types.NoSuchKey); errors.As(err, &noKey) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("get %s from bucket %s: %w", key, bucket, err)
	}
	defer func() { _ = out.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(out.Body, MaxReportBytes+1))
	if err != nil {
		return nil, false, fmt.Errorf("read %s from bucket %s: %w", key, bucket, err)
	}
	if len(body) > MaxReportBytes {
		return nil, false, fmt.Errorf("read %s: %w", key, ErrReportTooLarge)
	}
	return body, true, nil
}
