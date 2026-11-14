package harness

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
	"testing"
	"time"
)

// signalling is a recorder that tells when a kind is truncated.
type signalling struct {
	*recorder
	truncated chan string
}

func (s signalling) truncate(kind ObservationKind, why string) {
	s.recorder.truncate(kind, why)
	s.truncated <- why
}

// A client that reads its answers frees each request's slot: a session
// answers far more than maxPending requests, one after another.
func TestAnAnsweredRequestFreesItsSlot(t *testing.T) {
	answers, stdin := io.Pipe()
	stdout, server := io.Pipe()
	obs := signalling{newRecorder(func() time.Time { return testNow }), make(chan string, 1)}
	c := newConn(stdin, stdout, obs)
	replies := bufio.NewScanner(answers)
	for i := range maxPending * 4 {
		if _, err := fmt.Fprintf(server, `{"jsonrpc":"2.0","id":%d,"method":"elicitation/create","params":{}}`+"\n", i); err != nil {
			t.Fatal(err)
		}
		got := make(chan string, 1)
		go func() {
			replies.Scan()
			got <- replies.Text()
		}()
		select {
		case reply := <-got:
			var msg rpcMessage
			if json.Unmarshal([]byte(reply), &msg) != nil || string(msg.ID) != strconv.Itoa(i) {
				t.Fatalf("request %d got %q", i, reply)
			}
		case why := <-obs.truncated:
			t.Fatalf("request %d was dropped: %s", i, why)
		}
	}
	_ = server.Close()
	<-c.closed
	all := obs.all()
	if got := count(all, ObservedElicitation); got != maxRequestsPerKind {
		t.Errorf("%d elicitations observed, want the cap, %d", got, maxRequestsPerKind)
	}
}

func TestLargeRequestParamsAreKeptAsTheirStart(t *testing.T) {
	big := json.RawMessage(`{"message":"` + strings.Repeat("é", maxRequestParams) + `"}`)
	d := requestDetail(rpcMessage{Method: "sampling/createMessage", Params: big})
	var start string
	if !d.Cut || json.Unmarshal(d.Params, &start) != nil || len(start) > maxRequestParams+3 || !strings.HasPrefix(start, `{"message":"é`) {
		t.Errorf("cut %v, params of %d bytes, want the start of the params as a string", d.Cut, len(d.Params))
	}
	small := json.RawMessage(`{"maxTokens":100}`)
	if d := requestDetail(rpcMessage{Params: small}); d.Cut || string(d.Params) != string(small) {
		t.Errorf("small params %s cut %v, want them whole", d.Params, d.Cut)
	}
}
