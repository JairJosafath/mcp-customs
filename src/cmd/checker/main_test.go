package main

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
)

func TestTheJudgesClientTriesEachCallOnceUnderTheJudgesRetries(t *testing.T) {
	o := judgeClient(aws.Config{Region: "eu-west-1"}).Options()
	if o.RetryMaxAttempts != 1 || o.Retryer == nil || o.Retryer.MaxAttempts() != 1 {
		t.Errorf("RetryMaxAttempts %d, retryer %v; want one attempt", o.RetryMaxAttempts, o.Retryer)
	}
}
