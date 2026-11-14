package poller

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/lambda/types"

	"github.com/JairJosafath/mcp-customs/src/internal/store"
)

type fakeLambda struct {
	in  []*lambda.InvokeInput
	err error
}

func (f *fakeLambda) Invoke(_ context.Context, in *lambda.InvokeInput, _ ...func(*lambda.Options)) (*lambda.InvokeOutput, error) {
	f.in = append(f.in, in)
	return &lambda.InvokeOutput{}, f.err
}

func TestTheStarterInvokesTheCheckerAsynchronouslyNamedByTheCheckID(t *testing.T) {
	fake := &fakeLambda{}
	e := Event{
		CheckID:    "recheck-1",
		Submission: store.Submission{Kind: "go", Ref: "example.com/mail@v1.0.1"},
		Recheck:    Link{CheckID: "c0", Ref: "example.com/mail@v1.0.0", ToolListHash: "tools-v1"},
	}
	if err := NewLambdaStarter(fake, "arn:aws:lambda:us-east-1:111122223333:function:checker:$LATEST").Start(t.Context(), e); err != nil {
		t.Fatal(err)
	}
	in := fake.in[0]
	if aws.ToString(in.FunctionName) != "arn:aws:lambda:us-east-1:111122223333:function:checker:$LATEST" ||
		in.InvocationType != types.InvocationTypeEvent || aws.ToString(in.DurableExecutionName) != "recheck-1" {
		t.Errorf("invoked %+v", in)
	}
	var got Event
	if err := json.Unmarshal(in.Payload, &got); err != nil || !reflect.DeepEqual(got, e) {
		t.Errorf("payload %s, want %+v", in.Payload, e)
	}
}

func TestTheStarterSaysWhenTheCheckWasAlreadyStarted(t *testing.T) {
	fake := &fakeLambda{err: &types.DurableExecutionAlreadyStartedException{Message: aws.String("already")}}
	if err := NewLambdaStarter(fake, "f").Start(t.Context(), Event{CheckID: "recheck-1"}); !errors.Is(err, ErrAlreadyStarted) {
		t.Errorf("error %v, want %v", err, ErrAlreadyStarted)
	}
	fake.err = errors.New("ServiceException")
	if err := NewLambdaStarter(fake, "f").Start(t.Context(), Event{CheckID: "recheck-1"}); err == nil || errors.Is(err, ErrAlreadyStarted) {
		t.Errorf("error %v, want Lambda's failure", err)
	}
}
