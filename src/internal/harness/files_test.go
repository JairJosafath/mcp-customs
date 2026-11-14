package harness

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A server that makes more files than a snapshot holds blinds the watch to
// the rest: the harness says so with one truncated observation of files.
func TestAFileWatchStoppedAtItsLimitIsATruncatedObservation(t *testing.T) {
	run := newTestRun(t, &fakeInstaller{})
	if status, body := run.do(t, http.MethodPost, "/install", installBody("go", "example.com/weather@v1.0.0")); status != http.StatusOK {
		t.Fatalf("POST /install = %d %v", status, body)
	}
	run.h.run.files.max = 3
	for _, name := range []string{"a", "b", "c", "d"} {
		if err := os.WriteFile(filepath.Join(run.home, name), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	_, body := run.do(t, http.MethodPost, "/list", nil)
	var got []struct {
		Kind   ObservationKind `json:"kind"`
		Detail TruncatedDetail `json:"detail"`
	}
	if err := json.Unmarshal(body["observations"], &got); err != nil {
		t.Fatal(err)
	}
	var truncated []TruncatedDetail
	for _, o := range got {
		if o.Kind == ObservedTruncated {
			truncated = append(truncated, o.Detail)
		}
	}
	if len(truncated) != 1 || truncated[0].Kind != ObservedFile || !strings.Contains(truncated[0].Why, "file watch stopped at 3 files") {
		t.Errorf("truncated observations %+v, want one saying the file watch stopped", truncated)
	}
}
