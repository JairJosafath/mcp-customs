package harness

import (
	"fmt"
	"io"
	"strings"
	"testing"
	"time"
)

// A server that sends request after request without reading the answers
// gets at most maxPending answered at once, each on a goroutine; past
// that, its requests are dropped and their kind stops being recorded.
func TestPendingRequestsOfTheServerAreCapped(t *testing.T) {
	_, stdin := io.Pipe() // nobody reads it: every answer waits
	stdout, server := io.Pipe()
	rec := newRecorder(func() time.Time { return testNow })
	c := newConn(stdin, stdout, rec)
	const sent = maxPending * 3
	go func() {
		for i := range sent {
			_, _ = fmt.Fprintf(server, `{"jsonrpc":"2.0","id":%d,"method":"sampling/createMessage","params":{}}`+"\n", i)
		}
		_ = server.Close()
	}()
	<-c.closed
	all := rec.all()
	// The writer takes one answer off a goroutine before it blocks, so one
	// more slot may have come free.
	if got := count(all, ObservedSampling); got < maxPending || got > maxPending+1 {
		t.Errorf("%d of %d requests observed, want the %d answered at once", got, sent, maxPending)
	}
	if got := truncations(all); len(got) != 1 || got[0].Kind != ObservedSampling {
		t.Errorf("truncated observations %+v, want one of sampling", got)
	}
}

func TestARequestWithAnOverlongIDIsObservedNotKeptToAnswer(t *testing.T) {
	_, stdin := io.Pipe()
	stdout, server := io.Pipe()
	rec := newRecorder(func() time.Time { return testNow })
	c := newConn(stdin, stdout, rec)
	go func() {
		id := `"` + strings.Repeat("1", maxRequestID) + `"`
		_, _ = fmt.Fprintf(server, `{"jsonrpc":"2.0","id":%s,"method":"elicitation/create","params":{}}`+"\n", id)
		_ = server.Close()
	}()
	<-c.closed
	if got := count(rec.all(), ObservedElicitation); got != 1 {
		t.Errorf("%d elicitations observed, want 1", got)
	}
	if got := len(c.slots); got != 0 {
		t.Errorf("%d requests pending, want none for an id no client keeps", got)
	}
}
