package store

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
)

// fakeS3Get answers GetObject from objects, by bucket and key; a missing
// key is S3's NoSuchKey, and err makes every get fail.
type fakeS3Get struct {
	objects map[string]string
	err     error
	keys    []string
}

func (f *fakeS3Get) GetObject(_ context.Context, in *s3.GetObjectInput, _ ...func(*s3.Options)) (*s3.GetObjectOutput, error) {
	key := aws.ToString(in.Bucket) + "/" + aws.ToString(in.Key)
	f.keys = append(f.keys, key)
	if f.err != nil {
		return nil, f.err
	}
	body, ok := f.objects[key]
	if !ok {
		return nil, &types.NoSuchKey{}
	}
	return &s3.GetObjectOutput{Body: io.NopCloser(strings.NewReader(body))}, nil
}

func TestReportReaderReadsTheReportOfACheck(t *testing.T) {
	fake := &fakeS3Get{objects: map[string]string{"b/reports/c1.json": `{"verdict":"pass"}`}}
	body, found, err := NewReportReader(fake, "b").GetReport(t.Context(), "c1")
	if err != nil || !found || string(body) != `{"verdict":"pass"}` {
		t.Errorf("GetReport = %q, %v, %v", body, found, err)
	}
	if len(fake.keys) != 1 || fake.keys[0] != "b/reports/c1.json" {
		t.Errorf("read %v, want only b/reports/c1.json", fake.keys)
	}
}

func TestReportReaderAnswersNotFoundForACheckWithoutAReport(t *testing.T) {
	body, found, err := NewReportReader(&fakeS3Get{objects: map[string]string{}}, "b").GetReport(t.Context(), "c1")
	if err != nil || found || body != nil {
		t.Errorf("GetReport = %q, %v, %v; want nothing, not found", body, found, err)
	}
}

func TestReportReaderRefusesWhatItShouldNotRead(t *testing.T) {
	for name, tc := range map[string]struct {
		fake *fakeS3Get
		id   string
		want error
	}{
		"a path for an id": {&fakeS3Get{}, "../observations/c1", ErrBadCheckID},
		"a report too large": {
			&fakeS3Get{objects: map[string]string{"b/reports/c1.json": strings.Repeat("a", MaxReportBytes+1)}},
			"c1", ErrReportTooLarge,
		},
		"an outage": {&fakeS3Get{err: errOutage}, "c1", errOutage},
	} {
		_, found, err := NewReportReader(tc.fake, "b").GetReport(t.Context(), tc.id)
		if found || !errors.Is(err, tc.want) {
			t.Errorf("%s: found %v, err %v; want %v", name, found, err, tc.want)
		}
	}
}

var errOutage = errors.New("service unavailable")
