// The Checker: a Lambda durable function. Wiring only; the work is in
// internal/checker.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/aws/aws-durable-execution-sdk-go/durable"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/lambdamicrovms"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"

	"github.com/JairJosafath/mcp-customs/src/internal/canary"
	"github.com/JairJosafath/mcp-customs/src/internal/checker"
	"github.com/JairJosafath/mcp-customs/src/internal/checker/bedrock"
	"github.com/JairJosafath/mcp-customs/src/internal/checker/sandbox"
	"github.com/JairJosafath/mcp-customs/src/internal/store"
)

// harnessTimeout bounds one Harness API call, an install included: under
// the Checker's five minutes an invocation.
const harnessTimeout = 4 * time.Minute

func main() {
	// Lambda sends what the function writes to CloudWatch Logs, one entry a line.
	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	env := map[string]string{}
	for _, name := range []string{
		"DYNAMODB_TABLE_NAME", "REPORTS_BUCKET_NAME",
		"SANDBOX_IMAGE_ARN", "SANDBOX_INGRESS_CONNECTOR_ARN", "SANDBOX_EGRESS_CONNECTOR_ARN",
		"RUN_TOKEN_SECRET_ARN", "JUDGE_MODEL_ID", "API_HOST",
	} {
		env[name] = os.Getenv(name)
		if env[name] == "" {
			log.Error("A variable the stack sets is not set.", "variable", name)
			os.Exit(1)
		}
	}
	// Created once per execution environment, before the first invocation,
	// so warm invocations reuse the clients and their connections. The SDK
	// makes its own Lambda client for checkpoints on the first invocation,
	// and keeps it.
	cfg, err := config.LoadDefaultConfig(context.Background())
	if err != nil {
		log.Error("Loading the AWS configuration failed.", "error", err.Error())
		os.Exit(1)
	}
	// The key run tokens are derived from, read once: a token is never kept
	// in an execution's history, so every invocation derives it again.
	secret, err := secretsmanager.NewFromConfig(cfg).GetSecretValue(context.Background(), &secretsmanager.GetSecretValueInput{
		SecretId: aws.String(env["RUN_TOKEN_SECRET_ARN"]),
	})
	if err != nil || aws.ToString(secret.SecretString) == "" {
		log.Error("Reading the run token key failed.", "secret", env["RUN_TOKEN_SECRET_ARN"], "error", fmt.Sprint(err))
		os.Exit(1)
	}
	key := []byte(aws.ToString(secret.SecretString))
	vms := sandbox.NewMicroVMs(lambdamicrovms.NewFromConfig(cfg), &http.Client{Timeout: harnessTimeout}, sandbox.Config{
		ImageARN:            env["SANDBOX_IMAGE_ARN"],
		IngressConnectorARN: env["SANDBOX_INGRESS_CONNECTOR_ARN"],
		EgressConnectorARN:  env["SANDBOX_EGRESS_CONNECTOR_ARN"],
	})
	deps := checker.Deps{
		Store:    store.New(dynamodb.NewFromConfig(cfg), env["DYNAMODB_TABLE_NAME"]),
		Reports:  store.NewBucket(s3.NewFromConfig(cfg), env["REPORTS_BUCKET_NAME"]),
		Sandbox:  vms,
		Judge:    bedrock.New(bedrockruntime.NewFromConfig(cfg), env["JUDGE_MODEL_ID"]),
		Canaries: canary.New,
		Token:    func(checkID string) string { return sandbox.DeriveRunToken(key, checkID) },
		// The stack's own API, which no allowlist may reach.
		APIHost:    env["API_HOST"],
		LookupHost: net.DefaultResolver.LookupHost,
	}
	durable.Start(checker.Handler(deps), durable.WithLogHandler(log.Handler()))
}
