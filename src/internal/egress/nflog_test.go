package egress

import (
	"os"
	"testing"

	"github.com/JairJosafath/mcp-customs/src/internal/findings"
)

func TestAReaderOfRefusedPacketsThatStopsIsRecordedForReview(t *testing.T) {
	// A pipe stands in for the netlink socket: reading it fails, as a
	// socket the kernel errors on would.
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = w.Close() })
	raw, err := r.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	n := &NFLog{fd: int(r.Fd()), group: 47, file: r, raw: raw}
	t.Cleanup(func() { _ = n.Close() })
	rec := newRecorded()
	e := New(Config{})
	e.Observe(rec.observe)
	if err := e.ServeNFLog(n); err == nil {
		t.Error("ServeNFLog = nil, want the read's error")
	}
	obs := rec.of(KindConnect)
	if len(obs) != 1 {
		t.Fatalf("connect observations = %+v, want one saying the reader stopped", obs)
	}
	if d, _ := obs[0].(ConnectDetail); d.Via != "direct" || d.Stopped == "" {
		t.Errorf("stopped = %+v", d)
	}
	if found := leftAs(t, rec); !hasRule(found, findings.RuleDirectUnrecorded) {
		t.Errorf("findings = %+v, want %s", found, findings.RuleDirectUnrecorded)
	}
}
