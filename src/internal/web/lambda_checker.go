package web

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/lambda/types"

	"github.com/JairJosafath/mcp-customs/src/internal/store"
)

// LambdaAPI is the part of Lambda's client the web function calls, so a
// test passes a fake without the network.
type LambdaAPI interface {
	Invoke(ctx context.Context, in *lambda.InvokeInput, opts ...func(*lambda.Options)) (*lambda.InvokeOutput, error)
	SendDurableExecutionCallbackSuccess(
		ctx context.Context, in *lambda.SendDurableExecutionCallbackSuccessInput, opts ...func(*lambda.Options),
	) (*lambda.SendDurableExecutionCallbackSuccessOutput, error)
}

// LambdaChecker starts checks on the Checker, a durable function, and
// answers the ones waiting for a person through their callbacks.
type LambdaChecker struct {
	client LambdaAPI
	// function is the Checker's qualified ARN: a durable function is
	// invoked only by version, alias or $LATEST.
	function string
}

// NewLambdaChecker returns the Checker at the qualified ARN function,
// reached through client.
func NewLambdaChecker(client LambdaAPI, function string) *LambdaChecker {
	return &LambdaChecker{client: client, function: function}
}

// startEvent is the event that starts a check, the Checker's Input.
type startEvent struct {
	CheckID    string           `json:"checkId"`
	Submission store.Submission `json:"submission"`
}

// Start invokes the Checker asynchronously, with the check's ID as the
// durable execution's name: the same ID and submission again return the
// execution already started instead of a second one.
func (c *LambdaChecker) Start(ctx context.Context, checkID string, s store.Submission) error {
	payload, err := json.Marshal(startEvent{CheckID: checkID, Submission: s})
	if err != nil {
		return fmt.Errorf("encode the start of check %s: %w", checkID, err)
	}
	_, err = c.client.Invoke(ctx, &lambda.InvokeInput{
		FunctionName:         aws.String(c.function),
		InvocationType:       types.InvocationTypeEvent,
		DurableExecutionName: aws.String(checkID),
		Payload:              payload,
	})
	if started := new(types.DurableExecutionAlreadyStartedException); errors.As(err, &started) {
		return fmt.Errorf("start check %s: %w", checkID, ErrAlreadyStarted)
	}
	if err != nil {
		return fmt.Errorf("invoke the Checker for check %s: %w", checkID, err)
	}
	return nil
}

// Answer sends decision to the waiting check's callback callbackID, as
// {"decision":"approve"} or {"decision":"block"}.
func (c *LambdaChecker) Answer(ctx context.Context, callbackID, decision string) error {
	result, err := json.Marshal(struct {
		Decision string `json:"decision"`
	}{decision})
	if err != nil {
		return fmt.Errorf("encode the decision: %w", err)
	}
	_, err = c.client.SendDurableExecutionCallbackSuccess(ctx, &lambda.SendDurableExecutionCallbackSuccessInput{
		CallbackId: aws.String(callbackID),
		Result:     result,
	})
	if closed := new(types.CallbackTimeoutException); errors.As(err, &closed) {
		return ErrCallbackClosed
	}
	if err != nil {
		return fmt.Errorf("send the decision to the Checker's callback: %w", err)
	}
	return nil
}
