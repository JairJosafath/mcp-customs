package web

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/lambda/types"

	"github.com/JairJosafath/mcp-customs/src/internal/store"
)

// fakeLambda records the calls made and answers err.
type fakeLambda struct {
	invokes   []*lambda.InvokeInput
	callbacks []*lambda.SendDurableExecutionCallbackSuccessInput
	err       error
}

func (f *fakeLambda) Invoke(_ context.Context, in *lambda.InvokeInput, _ ...func(*lambda.Options)) (*lambda.InvokeOutput, error) {
	f.invokes = append(f.invokes, in)
	return &lambda.InvokeOutput{StatusCode: 202}, f.err
}

func (f *fakeLambda) SendDurableExecutionCallbackSuccess(
	_ context.Context, in *lambda.SendDurableExecutionCallbackSuccessInput, _ ...func(*lambda.Options),
) (*lambda.SendDurableExecutionCallbackSuccessOutput, error) {
	f.callbacks = append(f.callbacks, in)
	return &lambda.SendDurableExecutionCallbackSuccessOutput{}, f.err
}

const checkerARN = "arn:aws:lambda:us-east-1:123456789012:function:Checker:$LATEST"

func TestStartInvokesTheCheckerAsynchronouslyUnderTheChecksName(t *testing.T) {
	fake := &fakeLambda{}
	err := NewLambdaChecker(fake, checkerARN).Start(t.Context(), "c1", store.Submission{Kind: "npm", Ref: "x@1.0.0"})
	if err != nil || len(fake.invokes) != 1 {
		t.Fatalf("Start = %v, invokes %v", err, fake.invokes)
	}
	in := fake.invokes[0]
	if aws.ToString(in.FunctionName) != checkerARN || in.InvocationType != types.InvocationTypeEvent ||
		aws.ToString(in.DurableExecutionName) != "c1" ||
		string(in.Payload) != `{"checkId":"c1","submission":{"kind":"npm","ref":"x@1.0.0"}}` {
		t.Errorf("invoked %s %s %s %s", aws.ToString(in.FunctionName), in.InvocationType, aws.ToString(in.DurableExecutionName), in.Payload)
	}
}

func TestAnswerSendsTheDecisionToTheCallback(t *testing.T) {
	fake := &fakeLambda{}
	if err := NewLambdaChecker(fake, checkerARN).Answer(t.Context(), "cb-1", "block"); err != nil || len(fake.callbacks) != 1 {
		t.Fatalf("Answer = %v, callbacks %v", err, fake.callbacks)
	}
	if in := fake.callbacks[0]; aws.ToString(in.CallbackId) != "cb-1" || string(in.Result) != `{"decision":"block"}` {
		t.Errorf("sent %s %s", aws.ToString(in.CallbackId), in.Result)
	}
}

func TestTheCheckersErrorsAreOnesAPersonCanActOn(t *testing.T) {
	outage := errors.New("throttled")
	for name, tc := range map[string]struct {
		err  error
		call func(*LambdaChecker) error
		want error
	}{
		"a name taken": {
			&types.DurableExecutionAlreadyStartedException{},
			func(c *LambdaChecker) error { return c.Start(t.Context(), "c1", store.Submission{}) },
			ErrAlreadyStarted,
		},
		"a callback closed": {
			&types.CallbackTimeoutException{},
			func(c *LambdaChecker) error { return c.Answer(t.Context(), "cb-1", "approve") },
			ErrCallbackClosed,
		},
		"an outage starting": {
			outage, func(c *LambdaChecker) error { return c.Start(t.Context(), "c1", store.Submission{}) }, outage,
		},
		"an outage answering": {
			outage, func(c *LambdaChecker) error { return c.Answer(t.Context(), "cb-1", "approve") }, outage,
		},
	} {
		if err := tc.call(NewLambdaChecker(&fakeLambda{err: tc.err}, checkerARN)); !errors.Is(err, tc.want) {
			t.Errorf("%s: %v, want %v", name, err, tc.want)
		}
	}
}
