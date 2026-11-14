// The web function: the HTTP API's pages and JSON API. Wiring only; the
// work is in internal/web.
package main

import (
	"context"
	"log/slog"
	"os"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"

	"github.com/JairJosafath/mcp-customs/src/internal/web"
)

func main() {
	// Lambda sends what the function writes to CloudWatch Logs, one entry a line.
	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	lambda.Start(func(ctx context.Context, req *events.APIGatewayV2HTTPRequest) (web.Response, error) {
		return web.Answer(ctx, req, log), nil
	})
}
