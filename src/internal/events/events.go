// Package events sends what a user can subscribe to on EventBridge: an
// approved check superseded by a re-check of a newer version that did not
// pass, and that mark lifted.
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

// Source, and SupersededType and LiftedType, are the events' source and
// detail-types, which a rule matches on: an approved check superseded by a
// re-check that code did not pass, and the mark lifted when a person
// approves that re-check after all.
const (
	Source         = "mcp-customs"
	SupersededType = "Approved check superseded"
	LiftedType     = "Approved check no longer superseded"
)

// API is the part of EventBridge's client the bus calls, so a test passes
// a fake without the network.
type API interface {
	PutEvents(ctx context.Context, in *eventbridge.PutEventsInput, opts ...func(*eventbridge.Options)) (*eventbridge.PutEventsOutput, error)
}

// Superseded is either event's detail: the approved check and its
// version's ref, and the re-check of a newer version with its verdict:
// review or block when superseded, pass when lifted.
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

// PutSuperseded sends that s's approved check is superseded. A retry may
// send it again: a subscriber tells the two apart by RecheckID.
func (b *Bus) PutSuperseded(ctx context.Context, s Superseded) error {
	return b.put(ctx, SupersededType, s)
}

// PutLifted sends that s's approved check is no longer superseded.
func (b *Bus) PutLifted(ctx context.Context, s Superseded) error {
	return b.put(ctx, LiftedType, s)
}

func (b *Bus) put(ctx context.Context, detailType string, s Superseded) error {
	detail, err := json.Marshal(s)
	if err != nil {
		return fmt.Errorf("encode the %q event: %w", detailType, err)
	}
	out, err := b.client.PutEvents(ctx, &eventbridge.PutEventsInput{Entries: []types.PutEventsRequestEntry{{
		EventBusName: aws.String(b.name),
		Source:       aws.String(Source),
		DetailType:   aws.String(detailType),
		Detail:       aws.String(string(detail)),
	}}})
	if err != nil {
		return fmt.Errorf("put the %q event of check %s on bus %s: %w", detailType, s.ApprovedCheckID, b.name, err)
	}
	if out.FailedEntryCount > 0 {
		code := ""
		if len(out.Entries) > 0 {
			code = aws.ToString(out.Entries[0].ErrorCode)
		}
		return fmt.Errorf("put the %q event of check %s on bus %s (%s): %w", detailType, s.ApprovedCheckID, b.name, code, ErrNotPut)
	}
	return nil
}
