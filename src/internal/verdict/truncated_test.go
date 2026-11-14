package verdict

import (
	"encoding/json"
	"testing"

	"github.com/JairJosafath/mcp-customs/src/internal/findings"
)

// A kind the harness stopped recording, at a cap or at the file watch's
// limit, hides what the server did after: code says so, and the judge can't
// clear it.
func TestATruncatedObservationGivesReviewTheModelCantClear(t *testing.T) {
	for _, detail := range []string{
		`{"kind":"file","why":"the file watch stopped at 200000 files; files past them go unseen"}`,
		`{"kind":"dns","why":"more than 10000 dns observations"}`,
		`{"kind":"sampling","why":"more than 64 requests of the server unanswered at once"}`,
	} {
		obs := []findings.Observation{{At: "2026-11-14T12:00:00Z", Kind: findings.ObservedTruncated, Detail: json.RawMessage(detail)}}
		code := findings.FromObservations(obs, nil)
		got := Decide(Input{Code: code, ModelVerdict: Pass})
		if got.Verdict != Review {
			t.Errorf("%s: verdict %s, want review", detail, got.Verdict)
		}
		if len(got.Findings) != 1 || got.Findings[0].Rule != findings.RuleTruncated || got.Findings[0].Source != findings.Code {
			t.Errorf("%s: findings %+v, want one code %s", detail, got.Findings, findings.RuleTruncated)
		}
	}
}
