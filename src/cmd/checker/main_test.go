package main

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime"
)

func TestTheBedrockClientTriesEachCallOnceUnderTheJudgesRetries(t *testing.T) {
	o := bedrockruntime.NewFromConfig(aws.Config{Region: "eu-west-1"}, oneRetryPolicy).Options()
	if o.RetryMaxAttempts != 1 || o.Retryer == nil || o.Retryer.MaxAttempts() != 1 {
		t.Errorf("RetryMaxAttempts %d, retryer %v; want one attempt", o.RetryMaxAttempts, o.Retryer)
	}
}
