package bedrock

import (
	"errors"
	"slices"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/retry"
	"github.com/aws/smithy-go"
)

// busy are the Bedrock errors of a model that couldn't answer now but may
// next time: too busy, not ready, or failing or timing out on this one
// call. A call is safe to try again, as it changes nothing.
var busy = []string{
	"ThrottlingException", "ServiceUnavailableException", "ModelNotReadyException",
	"InternalServerException", "ModelTimeoutException",
}

// sdkRetryable classes an error as the SDK's standard retryer does: a
// connection reset, a 5xx, a throttle. The client's own retries are off
// (main's oneRetryPolicy), so the judge retries what the SDK would have.
var sdkRetryable = retry.IsErrorRetryables(retry.DefaultRetryables)

func isBusy(err error) bool {
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) && slices.Contains(busy, apiErr.ErrorCode()) {
		return true
	}
	return sdkRetryable.IsErrorRetryable(err) == aws.TrueTernary
}
