// The web function: the HTTP API's pages and JSON API. Wiring only; the
// work is in internal/web.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	awslambda "github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"

	"github.com/JairJosafath/mcp-customs/src/internal/store"
	"github.com/JairJosafath/mcp-customs/src/internal/web"
)

func main() {
	// Lambda sends what the function writes to CloudWatch Logs, one entry a line.
	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	env := map[string]string{}
	for _, name := range []string{"DYNAMODB_TABLE_NAME", "REPORTS_BUCKET_NAME", "CHECKER_FUNCTION_ARN", "REVIEWER_KEY_SECRET_ARN"} {
		env[name] = os.Getenv(name)
		if env[name] == "" {
			log.Error("A variable the stack sets is not set.", "variable", name)
			os.Exit(1)
		}
	}
	// Created once per execution environment, before the first invocation,
	// so warm invocations reuse the clients and their connections.
	cfg, err := config.LoadDefaultConfig(context.Background())
	if err != nil {
		log.Error("Loading the AWS configuration failed.", "error", err.Error())
		os.Exit(1)
	}
	// The key a person enters to Approve or Block, read once.
	secret, err := secretsmanager.NewFromConfig(cfg).GetSecretValue(context.Background(), &secretsmanager.GetSecretValueInput{
		SecretId: aws.String(env["REVIEWER_KEY_SECRET_ARN"]),
	})
	if err != nil || aws.ToString(secret.SecretString) == "" {
		log.Error("Reading the reviewer key failed.", "secret", env["REVIEWER_KEY_SECRET_ARN"], "error", fmt.Sprint(err))
		os.Exit(1)
	}
	objects := s3.NewFromConfig(cfg)
	h := web.New(web.Deps{
		Checks:      store.New(dynamodb.NewFromConfig(cfg), env["DYNAMODB_TABLE_NAME"]),
		Reports:     store.NewReportReader(objects, env["REPORTS_BUCKET_NAME"]),
		Proxy:       store.NewProxyReader(objects, env["REPORTS_BUCKET_NAME"]),
		Checker:     web.NewLambdaChecker(awslambda.NewFromConfig(cfg), env["CHECKER_FUNCTION_ARN"]),
		ReviewerKey: []byte(aws.ToString(secret.SecretString)),
		NewID:       web.NewCheckID,
		Log:         log,
	})
	lambda.Start(func(ctx context.Context, req *events.APIGatewayV2HTTPRequest) (web.Response, error) {
		return h.Answer(ctx, req), nil
	})
}
