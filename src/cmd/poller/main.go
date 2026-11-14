// The poller: run on a schedule, it starts a re-check of each approved
// package whose registry names a newer version. Wiring only; the work is
// in internal/poller.
package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	awslambda "github.com/aws/aws-sdk-go-v2/service/lambda"

	"github.com/JairJosafath/mcp-customs/src/internal/poller"
	"github.com/JairJosafath/mcp-customs/src/internal/store"
)

// registryTimeout bounds one registry request, well under the poller's
// minute an invocation.
const registryTimeout = 10 * time.Second

func main() {
	// Lambda sends what the function writes to CloudWatch Logs, one entry a line.
	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	env := map[string]string{}
	for _, name := range []string{"DYNAMODB_TABLE_NAME", "CHECKER_FUNCTION_ARN"} {
		env[name] = os.Getenv(name)
		if env[name] == "" {
			log.Error("A variable the stack sets is not set.", "variable", name)
			os.Exit(1)
		}
	}
	registries, err := poller.RegistriesFrom(os.Getenv)
	if err != nil {
		log.Error("A registry is not set right.", "error", err.Error())
		os.Exit(1)
	}
	// Created once per execution environment, before the first invocation,
	// so warm invocations reuse the clients and their connections.
	cfg, err := config.LoadDefaultConfig(context.Background())
	if err != nil {
		log.Error("Loading the AWS configuration failed.", "error", err.Error())
		os.Exit(1)
	}
	deps := poller.Deps{
		Approvals: store.New(dynamodb.NewFromConfig(cfg), env["DYNAMODB_TABLE_NAME"]),
		Registry:  poller.NewHTTPRegistry(&http.Client{Timeout: registryTimeout}, registries),
		Checker:   poller.NewLambdaStarter(awslambda.NewFromConfig(cfg), env["CHECKER_FUNCTION_ARN"]),
		Log:       log,
	}
	lambda.Start(func(ctx context.Context) (poller.Result, error) {
		res, err := poller.Poll(ctx, deps)
		log.InfoContext(ctx, "A poll ended.", "packages", res.Packages, "started", res.Started, "failed", res.Failed)
		return res, err
	})
}
