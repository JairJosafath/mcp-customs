package events

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/eventbridge"
	"github.com/aws/aws-sdk-go-v2/service/eventbridge/types"
)

type fakeEventBridge struct {
	in  []*eventbridge.PutEventsInput
	out *eventbridge.PutEventsOutput
	err error
}

func (f *fakeEventBridge) PutEvents(_ context.Context, in *eventbridge.PutEventsInput, _ ...func(*eventbridge.Options)) (*eventbridge.PutEventsOutput, error) {
	f.in = append(f.in, in)
	if f.out == nil {
		f.out = &eventbridge.PutEventsOutput{}
	}
	return f.out, f.err
}

func superseded() Superseded {
	return Superseded{
		ApprovedCheckID: "c0", ApprovedRef: "example.com/mail@v1.0.0", RecheckID: "recheck-1",
		Kind: "go", Ref: "example.com/mail@v1.0.1", Verdict: "block",
	}
}

func TestTheSupersededEventGoesToTheBusWithItsSourceTypeAndDetail(t *testing.T) {
	fake := &fakeEventBridge{}
	if err := NewBus(fake, "default").PutSuperseded(t.Context(), superseded()); err != nil {
		t.Fatal(err)
	}
	if len(fake.in) != 1 || len(fake.in[0].Entries) != 1 {
		t.Fatalf("sent %+v, want one event", fake.in)
	}
	e := fake.in[0].Entries[0]
	if aws.ToString(e.EventBusName) != "default" || aws.ToString(e.Source) != Source || aws.ToString(e.DetailType) != SupersededType {
		t.Errorf("event %+v, want bus default, source %s, type %s", e, Source, SupersededType)
	}
	var got Superseded
	if err := json.Unmarshal([]byte(aws.ToString(e.Detail)), &got); err != nil || got != superseded() {
		t.Errorf("detail %s (%v), want %+v", aws.ToString(e.Detail), err, superseded())
	}
}

func TestAnEventEventBridgeDidNotTakeIsAnError(t *testing.T) {
	for name, fake := range map[string]*fakeEventBridge{
		"a failed call": {err: errors.New("throttled")},
		"a failed entry": {out: &eventbridge.PutEventsOutput{
			FailedEntryCount: 1, Entries: []types.PutEventsResultEntry{{ErrorCode: aws.String("InternalFailure")}},
		}},
	} {
		if err := NewBus(fake, "default").PutSuperseded(t.Context(), superseded()); err == nil {
			t.Errorf("%s: PutSuperseded = nil, want an error", name)
		}
	}
	fake := &fakeEventBridge{out: &eventbridge.PutEventsOutput{FailedEntryCount: 1}}
	if err := NewBus(fake, "default").PutSuperseded(t.Context(), superseded()); !errors.Is(err, ErrNotPut) {
		t.Errorf("a failed entry: %v, want %v", err, ErrNotPut)
	}
}
