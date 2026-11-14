// Package events sends what a user can subscribe to on EventBridge: an
// approved check superseded by a re-check of a newer version that did not
// pass.
package events

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/eventbridge"
	"github.com/aws/aws-sdk-go-v2/service/eventbridge/types"
)

// Source and SupersededType are the event's source and detail-type, which
// a rule matches on.
const (
	Source         = "mcp-customs"
	SupersededType = "Approved check superseded"
)

// API is the part of EventBridge's client the bus calls, so a test passes
// a fake without the network.
type API interface {
	PutEvents(ctx context.Context, in *eventbridge.PutEventsInput, opts ...func(*eventbridge.Options)) (*eventbridge.PutEventsOutput, error)
}

// Superseded is the event's detail: the approved check and its version's
// ref, and the re-check of a newer version that ended at review or block.
type Superseded struct {
	ApprovedCheckID string `json:"approvedCheckId"`
	ApprovedRef     string `json:"approvedRef"`
	RecheckID       string `json:"recheckId"`
	Kind            string `json:"kind"`
	Ref             string `json:"ref"`
	Verdict         string `json:"verdict"`
}

// ErrNotPut says EventBridge answered but did not take the event.
var ErrNotPut = errors.New("EventBridge did not take the event")

// Bus sends events to one event bus.
type Bus struct {
	client API
	name   string
}

// NewBus returns the bus name, sending through client.
func NewBus(client API, name string) *Bus {
	return &Bus{client: client, name: name}
}

// PutSuperseded sends s. A retry may send it again: a subscriber tells
// the two apart by RecheckID.
func (b *Bus) PutSuperseded(ctx context.Context, s Superseded) error {
	detail, err := json.Marshal(s)
	if err != nil {
		return fmt.Errorf("encode the superseded event: %w", err)
	}
	out, err := b.client.PutEvents(ctx, &eventbridge.PutEventsInput{Entries: []types.PutEventsRequestEntry{{
		EventBusName: aws.String(b.name),
		Source:       aws.String(Source),
		DetailType:   aws.String(SupersededType),
		Detail:       aws.String(string(detail)),
	}}})
	if err != nil {
		return fmt.Errorf("put the superseded event of check %s on bus %s: %w", s.ApprovedCheckID, b.name, err)
	}
	if out.FailedEntryCount > 0 {
		code := ""
		if len(out.Entries) > 0 {
			code = aws.ToString(out.Entries[0].ErrorCode)
		}
		return fmt.Errorf("put the superseded event of check %s on bus %s (%s): %w", s.ApprovedCheckID, b.name, code, ErrNotPut)
	}
	return nil
}
