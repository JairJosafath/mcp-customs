package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

// ErrCheckDone says a check is done, so it is not marked failed.
var ErrCheckDone = errors.New("the check is done")

// FailCheck sets check id's status to failed unless it is done: a check
// marked done, with its approval when it passed, stays done whatever
// fails after. It answers ErrCheckDone then, and ErrNoCheck when the
// check doesn't exist, changing nothing either way.
func (s *Store) FailCheck(ctx context.Context, id string) error {
	pk, err := checkPK(id)
	if err != nil {
		return err
	}
	_, err = s.client.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName:                 aws.String(s.table),
		Key:                       row{"pk": str(pk), "sk": str(metaSK)},
		UpdateExpression:          aws.String("SET #status = :failed"),
		ConditionExpression:       aws.String("attribute_exists(pk) AND #status <> :done"),
		ExpressionAttributeNames:  map[string]string{"#status": "status"},
		ExpressionAttributeValues: row{":failed": str(string(StatusFailed)), ":done": str(string(StatusDone))},
	})
	if failed := new(types.ConditionalCheckFailedException); errors.As(err, &failed) {
		if _, found, getErr := s.GetCheck(ctx, id); getErr != nil || !found {
			return errors.Join(fmt.Errorf("fail check %s: %w", id, ErrNoCheck), getErr)
		}
		return fmt.Errorf("fail check %s: %w", id, ErrCheckDone)
	}
	if err != nil {
		return fmt.Errorf("fail check %s in table %s: %w", id, s.table, err)
	}
	return nil
}
