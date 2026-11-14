package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

// Superseding names a re-check that didn't pass and the package version it
// checked: kind, name and version key the package's APPROVED item.
type Superseding struct {
	RecheckID string
	Kind      string
	Name      string
	Version   string
}

// MarkSuperseded sets, on approved check approvedID's META, supersededBy
// to s's re-check, in one transaction with a check that s's version is
// still the newest the poller has polled, as PassCheck gates a
// re-check's approval. So, of two re-checks of one approval, the newer
// version's link stays whichever ends last; an older version's late
// review or block changes nothing. It answers whether it marked.
func (s *Store) MarkSuperseded(ctx context.Context, approvedID string, sup Superseding) (bool, error) {
	pk, err := checkPK(approvedID)
	if err != nil {
		return false, err
	}
	if !ValidCheckID(sup.RecheckID) {
		return false, ErrBadCheckID
	}
	sk, err := approvedSK(sup.Kind, sup.Name)
	if err != nil || sup.Version == "" {
		return false, ErrBadPackage
	}
	_, err = s.client.TransactWriteItems(ctx, &dynamodb.TransactWriteItemsInput{TransactItems: []types.TransactWriteItem{
		{ConditionCheck: &types.ConditionCheck{
			TableName:                 aws.String(s.table),
			Key:                       row{"pk": str(approvedPK), "sk": str(sk)},
			ConditionExpression:       aws.String("polled = :version"),
			ExpressionAttributeValues: row{":version": str(sup.Version)},
		}},
		{Update: &types.Update{
			TableName:                 aws.String(s.table),
			Key:                       row{"pk": str(pk), "sk": str(metaSK)},
			UpdateExpression:          aws.String("SET #supersededBy = :recheck"),
			ConditionExpression:       aws.String("attribute_exists(pk)"),
			ExpressionAttributeNames:  map[string]string{"#supersededBy": "supersededBy"},
			ExpressionAttributeValues: row{":recheck": str(sup.RecheckID)},
		}},
	}})
	if canceled := new(types.TransactionCanceledException); errors.As(err, &canceled) && conditionsFailed(canceled) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("mark check %s superseded by %s in table %s: %w", approvedID, sup.RecheckID, s.table, err)
	}
	return true, nil
}

// LiftSuperseded removes approved check approvedID's supersededBy while it
// names recheckID, as when a person approves the newer version after all,
// and answers whether it did: a link a newer re-check set stays. It keeps
// recheckID as liftedBy, so a retry of a lift that committed but lost its
// reply also answers true while no newer mark is set, and its event is sent.
func (s *Store) LiftSuperseded(ctx context.Context, approvedID, recheckID string) (bool, error) {
	pk, err := checkPK(approvedID)
	if err != nil {
		return false, err
	}
	_, err = s.client.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName:                 aws.String(s.table),
		Key:                       row{"pk": str(pk), "sk": str(metaSK)},
		UpdateExpression:          aws.String("REMOVE #supersededBy SET #liftedBy = :recheck"),
		ConditionExpression:       aws.String(liftCondition),
		ExpressionAttributeNames:  map[string]string{"#supersededBy": "supersededBy", "#liftedBy": "liftedBy"},
		ExpressionAttributeValues: row{":recheck": str(recheckID)},
	})
	if failed := new(types.ConditionalCheckFailedException); errors.As(err, &failed) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("lift the superseded mark of check %s in table %s: %w", approvedID, s.table, err)
	}
	return true, nil
}

// liftCondition holds while the mark names the re-check, or while no mark
// is set and the re-check is the one that lifted the last.
const liftCondition = "#supersededBy = :recheck OR (attribute_not_exists(#supersededBy) AND #liftedBy = :recheck)"

// conditionsFailed reports whether a transaction was canceled only for
// conditions that didn't hold, not a conflict or a throttle.
func conditionsFailed(e *types.TransactionCanceledException) bool {
	failed := false
	for _, r := range e.CancellationReasons {
		switch aws.ToString(r.Code) {
		case "None", "":
		case "ConditionalCheckFailed":
			failed = true
		default:
			return false
		}
	}
	return failed
}
