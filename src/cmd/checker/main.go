// The Checker: a Lambda durable function. Wiring only; the work is in
// internal/checker.
package main

import (
	"context"
	"log/slog"
	"os"

	"github.com/aws/aws-durable-execution-sdk-go/durable"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"

	"github.com/JairJosafath/mcp-customs/src/internal/checker"
	"github.com/JairJosafath/mcp-customs/src/internal/store"
)

func main() {
	// Lambda sends what the function writes to CloudWatch Logs, one entry a line.
	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	table := os.Getenv("DYNAMODB_TABLE_NAME")
	if table == "" {
		log.Error("DYNAMODB_TABLE_NAME is not set; the stack sets it to the table the Checker writes.")
		os.Exit(1)
	}
	// Created once per execution environment, before the first invocation,
	// so warm invocations reuse the client and its connections. The SDK
	// makes its own Lambda client for checkpoints on the first invocation,
	// and keeps it.
	cfg, err := config.LoadDefaultConfig(context.Background())
	if err != nil {
		log.Error("Loading the AWS configuration failed.", "error", err.Error())
		os.Exit(1)
	}
	st := store.New(dynamodb.NewFromConfig(cfg), table)
	durable.Start(checker.Handler(st), durable.WithLogHandler(log.Handler()))
}
