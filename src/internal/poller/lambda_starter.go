package poller

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/lambda/types"
)

// LambdaAPI is the part of Lambda's client the poller calls, so a test
// passes a fake without the network.
type LambdaAPI interface {
	Invoke(ctx context.Context, in *lambda.InvokeInput, opts ...func(*lambda.Options)) (*lambda.InvokeOutput, error)
}

// LambdaStarter starts checks on the Checker, a durable function.
type LambdaStarter struct {
	client LambdaAPI
	// function is the Checker's qualified ARN: a durable function is
	// invoked only by version, alias or $LATEST.
	function string
}

// NewLambdaStarter returns the Checker at the qualified ARN function,
// reached through client.
func NewLambdaStarter(client LambdaAPI, function string) *LambdaStarter {
	return &LambdaStarter{client: client, function: function}
}

// Start invokes the Checker asynchronously with e, the check's ID as the
// durable execution's name, so the same ID never starts a second one.
func (s *LambdaStarter) Start(ctx context.Context, e Event) error {
	payload, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("encode the start of check %s: %w", e.CheckID, err)
	}
	_, err = s.client.Invoke(ctx, &lambda.InvokeInput{
		FunctionName:         aws.String(s.function),
		InvocationType:       types.InvocationTypeEvent,
		DurableExecutionName: aws.String(e.CheckID),
		Payload:              payload,
	})
	if started := new(types.DurableExecutionAlreadyStartedException); errors.As(err, &started) {
		return fmt.Errorf("start check %s: %w", e.CheckID, ErrAlreadyStarted)
	}
	if err != nil {
		return fmt.Errorf("invoke the Checker for check %s: %w", e.CheckID, err)
	}
	return nil
}
