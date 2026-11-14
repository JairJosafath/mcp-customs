package store

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"regexp"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// S3API is the part of S3's client the bucket calls, so a test passes a
// fake without the network.
type S3API interface {
	PutObject(ctx context.Context, in *s3.PutObjectInput, opts ...func(*s3.Options)) (*s3.PutObjectOutput, error)
}

// Bucket keeps each check's report and raw observations as JSON objects,
// as docs/contracts.md ("Store") names them. A retried write puts the same
// whole object again.
type Bucket struct {
	client S3API
	name   string
}

// NewBucket returns the bucket name, sending through client.
func NewBucket(client S3API, name string) *Bucket {
	return &Bucket{client: client, name: name}
}

// PutReport writes check checkID's report, reports/<check-id>.json.
func (b *Bucket) PutReport(ctx context.Context, checkID string, report []byte) error {
	if !ValidCheckID(checkID) {
		return ErrBadCheckID
	}
	return b.put(ctx, "reports/", checkID, report)
}

// PutObservations writes check checkID's raw observations,
// observations/<check-id>.json.
func (b *Bucket) PutObservations(ctx context.Context, checkID string, observations []byte) error {
	if !ValidCheckID(checkID) {
		return ErrBadCheckID
	}
	return b.put(ctx, "observations/", checkID, observations)
}

// PutOversized writes an answer of check checkID too large for a step to
// keep, observations/<check-id>-<what>.json; what is the Checker's own
// name for it, such as list or call-3.
func (b *Bucket) PutOversized(ctx context.Context, checkID, what string, body []byte) error {
	if !ValidCheckID(checkID) {
		return ErrBadCheckID
	}
	if !whatPattern.MatchString(what) {
		return ErrBadWhat
	}
	return b.put(ctx, "observations/", checkID+"-"+what, body)
}

// ErrBadWhat says an oversized answer's name isn't one the Checker makes.
var ErrBadWhat = errors.New("an oversized answer's name must be 1 to 32 lowercase letters, digits or -")

var whatPattern = regexp.MustCompile(`^[a-z0-9-]{1,32}$`)

func (b *Bucket) put(ctx context.Context, prefix, checkID string, body []byte) error {
	key := prefix + checkID + ".json"
	_, err := b.client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:      aws.String(b.name),
		Key:         aws.String(key),
		Body:        bytes.NewReader(body),
		ContentType: aws.String("application/json"),
	})
	if err != nil {
		return fmt.Errorf("put %s into bucket %s: %w", key, b.name, err)
	}
	return nil
}
