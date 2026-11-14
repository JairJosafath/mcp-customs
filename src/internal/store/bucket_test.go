package store

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// fakeS3 keeps each object put, by bucket and key; err makes every put fail.
type fakeS3 struct {
	objects map[string]string
	types   map[string]string
	err     error
}

func (f *fakeS3) PutObject(_ context.Context, in *s3.PutObjectInput, _ ...func(*s3.Options)) (*s3.PutObjectOutput, error) {
	if f.err != nil {
		return nil, f.err
	}
	body, err := io.ReadAll(in.Body)
	if err != nil {
		return nil, err
	}
	key := aws.ToString(in.Bucket) + "/" + aws.ToString(in.Key)
	f.objects[key] = string(body)
	f.types[key] = aws.ToString(in.ContentType)
	return &s3.PutObjectOutput{}, nil
}

func TestBucketPutsReportsAndObservationsUnderTheContractsKeys(t *testing.T) {
	fake := &fakeS3{objects: map[string]string{}, types: map[string]string{}}
	b := NewBucket(fake, "reports-bucket")
	if err := b.PutReport(t.Context(), "c1", []byte(`{"verdict":"pass"}`)); err != nil {
		t.Fatal(err)
	}
	if err := b.PutObservations(t.Context(), "c1", []byte(`[]`)); err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"reports-bucket/reports/c1.json":      `{"verdict":"pass"}`,
		"reports-bucket/observations/c1.json": `[]`,
	}
	for key, body := range want {
		if fake.objects[key] != body || fake.types[key] != "application/json" {
			t.Errorf("%s = %q (%s), want %q as JSON", key, fake.objects[key], fake.types[key], body)
		}
	}
}

func TestBucketRefusesABadCheckIDAndReportsAFailedPut(t *testing.T) {
	fake := &fakeS3{objects: map[string]string{}, types: map[string]string{}}
	if err := NewBucket(fake, "b").PutReport(t.Context(), "../c1", nil); !errors.Is(err, ErrBadCheckID) {
		t.Errorf("a bad id: %v, want %v", err, ErrBadCheckID)
	}
	if len(fake.objects) != 0 {
		t.Errorf("put %v", fake.objects)
	}
	fake.err = errors.New("service unavailable")
	err := NewBucket(fake, "b").PutReport(t.Context(), "c1", nil)
	if !errors.Is(err, fake.err) || !strings.Contains(err.Error(), "reports/c1.json") {
		t.Errorf("an outage: %v, want it wrapped, naming the key", err)
	}
}

func TestBucketPutsAnOversizedAnswerBesideTheObservations(t *testing.T) {
	fake := &fakeS3{objects: map[string]string{}, types: map[string]string{}}
	b := NewBucket(fake, "b")
	if err := b.PutOversized(t.Context(), "c1", "call-3", []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	if fake.objects["b/observations/c1-call-3.json"] != `{}` {
		t.Errorf("objects %v, want observations/c1-call-3.json", fake.objects)
	}
	for _, what := range []string{"", "../x", "Call", strings.Repeat("a", 33)} {
		if err := b.PutOversized(t.Context(), "c1", what, nil); !errors.Is(err, ErrBadWhat) {
			t.Errorf("%q: %v, want %v", what, err, ErrBadWhat)
		}
	}
	if err := b.PutOversized(t.Context(), "c/1", "list", nil); !errors.Is(err, ErrBadCheckID) {
		t.Errorf("a bad id: %v", err)
	}
}
