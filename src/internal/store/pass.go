package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

// Pass is what a check that approved a server writes as it ends.
type Pass struct {
	// Hash is the approval of the check's dependency-set hash: its HASH#
	// item, which names the check.
	Hash Verdict
	// Approved is the package's APPROVED item, nil for a remote server.
	Approved *Approved
	// Conditional gates Approved. The APPROVED item is written with Polled
	// set to its version. A fresh approval (Conditional false) is written
	// whatever was there before. A re-check's approval (Conditional true)
	// is written only while the package's newest polled version, the
	// version the poller started this re-check for, is still its version,
	// or the package has no approval yet. So, of several re-checks racing
	// from one approval, only the one for the newest version the poller has
	// seen wins, whichever finishes first; an older version's late pass, or
	// a re-check overtaken by a newer poll, leaves the approval as it is.
	// The gate is the version, held in `polled`, which the poller only ever
	// advances (MarkPolled), not the order the re-checks finished in.
	Conditional bool
	// Verdict is the verdict the check's META is marked done with.
	Verdict string
}

// PassCheck writes, in one transaction, p's HASH# item, its APPROVED item
// and check p.Hash.CheckID's META as done with p's verdict: either all of
// them or none, so no approval is left of a check that could not be
// marked done. A conditional approval whose condition doesn't hold is left
// out and the rest written. It answers
// ErrNoCheck when the check doesn't exist, writing nothing.
func (s *Store) PassCheck(ctx context.Context, p Pass) error {
	items, err := s.passItems(p)
	if err != nil {
		return err
	}
	_, err = s.client.TransactWriteItems(ctx, &dynamodb.TransactWriteItemsInput{TransactItems: items})
	if canceled := new(types.TransactionCanceledException); errors.As(err, &canceled) && conditionsFailed(canceled) {
		reasons := canceled.CancellationReasons
		if len(reasons) == 3 && failedCondition(reasons[1]) && !failedCondition(reasons[2]) {
			// A newer version has been polled or approved: leave it.
			p.Approved = nil
			return s.PassCheck(ctx, p)
		}
		return fmt.Errorf("pass check %s: %w", p.Hash.CheckID, ErrNoCheck)
	}
	if err != nil {
		return fmt.Errorf("pass check %s in table %s: %w", p.Hash.CheckID, s.table, err)
	}
	return nil
}

// passItems are PassCheck's writes: the HASH# item, the APPROVED item when
// there is one, and the META update, last.
func (s *Store) passItems(p Pass) ([]types.TransactWriteItem, error) {
	hash, err := hashPK(p.Hash.Hash)
	if err != nil {
		return nil, err
	}
	meta, err := checkPK(p.Hash.CheckID)
	if err != nil {
		return nil, err
	}
	expr, names, values, err := checkSets(CheckUpdate{Status: StatusDone, Verdict: p.Verdict})
	if err != nil {
		return nil, err
	}
	items := []types.TransactWriteItem{{Put: &types.Put{TableName: aws.String(s.table), Item: verdictRow(hash, p.Hash)}}}
	if a := p.Approved; a != nil {
		sk, err := approvedSK(a.Kind, a.Name)
		if err != nil || a.Version == "" {
			return nil, ErrBadPackage
		}
		a.Polled = a.Version
		put := &types.Put{TableName: aws.String(s.table), Item: approvedRow(sk, *a)}
		if p.Conditional {
			put.ConditionExpression = aws.String("attribute_not_exists(pk) OR polled = :version")
			put.ExpressionAttributeValues = row{":version": str(a.Version)}
		}
		items = append(items, types.TransactWriteItem{Put: put})
	}
	return append(items, types.TransactWriteItem{Update: &types.Update{
		TableName:                 aws.String(s.table),
		Key:                       row{"pk": str(meta), "sk": str(metaSK)},
		UpdateExpression:          aws.String(expr),
		ConditionExpression:       aws.String("attribute_exists(pk)"),
		ExpressionAttributeNames:  names,
		ExpressionAttributeValues: values,
	}}), nil
}

func failedCondition(r types.CancellationReason) bool {
	return aws.ToString(r.Code) == "ConditionalCheckFailed"
}
