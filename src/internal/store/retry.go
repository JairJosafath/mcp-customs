package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

// MarkRetry asks, on package kind and name's APPROVED item, for the
// re-check of version to be retried: the Checker calls it when that
// re-check failed, and the poller, which reads only APPROVED items, starts
// the retry. It marks only while version is still the newest the poller
// has polled, and answers whether it did: a re-check overtaken by a newer
// version, or of a package no longer approved, is not retried.
func (s *Store) MarkRetry(ctx context.Context, kind, name, version string) (bool, error) {
	sk, err := approvedSK(kind, name)
	if err != nil || version == "" {
		return false, ErrBadPackage
	}
	_, err = s.client.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName:                 aws.String(s.table),
		Key:                       row{"pk": str(approvedPK), "sk": str(sk)},
		UpdateExpression:          aws.String("SET #retry = :version"),
		ConditionExpression:       aws.String("polled = :version"),
		ExpressionAttributeNames:  map[string]string{"#retry": "retry"},
		ExpressionAttributeValues: row{":version": str(version)},
	})
	if failed := new(types.ConditionalCheckFailedException); errors.As(err, &failed) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("ask a retry of %s at %s in table %s: %w", sk, version, s.table, err)
	}
	return true, nil
}

// ClearRetry removes the poller's ask for a retry of version, once it has
// started it. An ask for another version, or none, is left as it is.
func (s *Store) ClearRetry(ctx context.Context, kind, name, version string) error {
	sk, err := approvedSK(kind, name)
	if err != nil || version == "" {
		return ErrBadPackage
	}
	_, err = s.client.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName:                 aws.String(s.table),
		Key:                       row{"pk": str(approvedPK), "sk": str(sk)},
		UpdateExpression:          aws.String("REMOVE #retry"),
		ConditionExpression:       aws.String("#retry = :version"),
		ExpressionAttributeNames:  map[string]string{"#retry": "retry"},
		ExpressionAttributeValues: row{":version": str(version)},
	})
	if failed := new(types.ConditionalCheckFailedException); errors.As(err, &failed) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("clear the retry of %s at %s in table %s: %w", sk, version, s.table, err)
	}
	return nil
}
