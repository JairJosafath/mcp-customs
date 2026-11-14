package store

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
)

// DynamoAPI is the part of DynamoDB's client the store calls, so a test
// passes a fake without the network.
type DynamoAPI interface {
	GetItem(ctx context.Context, in *dynamodb.GetItemInput, opts ...func(*dynamodb.Options)) (*dynamodb.GetItemOutput, error)
	PutItem(ctx context.Context, in *dynamodb.PutItemInput, opts ...func(*dynamodb.Options)) (*dynamodb.PutItemOutput, error)
	Query(ctx context.Context, in *dynamodb.QueryInput, opts ...func(*dynamodb.Options)) (*dynamodb.QueryOutput, error)
}

// Store keeps checks, their steps and verdicts in one table keyed by pk
// and sk. Every write puts a whole item, so a retried write changes nothing
// twice.
type Store struct {
	client DynamoAPI
	table  string
}

// New returns a store on table, sending through client.
func New(client DynamoAPI, table string) *Store {
	return &Store{client: client, table: table}
}

// PutCheck writes c's META item, replacing the one before.
func (s *Store) PutCheck(ctx context.Context, c Check) error {
	pk, err := checkPK(c.ID)
	if err != nil {
		return err
	}
	return s.put(ctx, checkRow(pk, c), "check "+c.ID)
}

// GetCheck reads check id's META item, and false when there is none.
func (s *Store) GetCheck(ctx context.Context, id string) (Check, bool, error) {
	pk, err := checkPK(id)
	if err != nil {
		return Check{}, false, err
	}
	r, err := s.get(ctx, pk, metaSK, "check "+id)
	if err != nil || r == nil {
		return Check{}, false, err
	}
	c, err := checkFrom(r)
	if err != nil {
		return Check{}, false, fmt.Errorf("read check %s: %w", id, err)
	}
	return c, true, nil
}

// AppendStep writes step as check checkID's STEP# item of its number.
func (s *Store) AppendStep(ctx context.Context, checkID string, step Step) error {
	pk, err := checkPK(checkID)
	if err != nil {
		return err
	}
	sk, err := stepSK(step.Seq)
	if err != nil {
		return err
	}
	r, err := stepRow(pk, sk, step)
	if err != nil {
		return err
	}
	return s.put(ctx, r, fmt.Sprintf("step %d of check %s", step.Seq, checkID))
}

// ListSteps reads check checkID's steps, in order.
func (s *Store) ListSteps(ctx context.Context, checkID string) ([]Step, error) {
	pk, err := checkPK(checkID)
	if err != nil {
		return nil, err
	}
	pages := dynamodb.NewQueryPaginator(s.client, &dynamodb.QueryInput{
		TableName:                 aws.String(s.table),
		KeyConditionExpression:    aws.String("pk = :pk AND begins_with(sk, :step)"),
		ExpressionAttributeValues: row{":pk": str(pk), ":step": str(stepPrefix)},
		ConsistentRead:            aws.Bool(true),
		ScanIndexForward:          aws.Bool(true),
	})
	steps := []Step{}
	for pages.HasMorePages() {
		page, err := pages.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("query the steps of check %s in table %s: %w", checkID, s.table, err)
		}
		for _, r := range page.Items {
			step, err := stepFrom(r)
			if err != nil {
				return nil, fmt.Errorf("read a step of check %s: %w", checkID, err)
			}
			steps = append(steps, step)
		}
	}
	return steps, nil
}

// PutVerdict writes v's HASH# item, replacing the one before.
func (s *Store) PutVerdict(ctx context.Context, v Verdict) error {
	pk, err := hashPK(v.Hash)
	if err != nil {
		return err
	}
	return s.put(ctx, verdictRow(pk, v), "the verdict of "+v.Hash)
}

// GetVerdict reads the verdict of hash, and false when there is none.
func (s *Store) GetVerdict(ctx context.Context, hash string) (Verdict, bool, error) {
	pk, err := hashPK(hash)
	if err != nil {
		return Verdict{}, false, err
	}
	r, err := s.get(ctx, pk, verdictSK, "the verdict of "+hash)
	if err != nil || r == nil {
		return Verdict{}, false, err
	}
	v, err := verdictFrom(r)
	if err != nil {
		return Verdict{}, false, fmt.Errorf("read the verdict of %s: %w", hash, err)
	}
	return v, true, nil
}

func (s *Store) put(ctx context.Context, r row, what string) error {
	_, err := s.client.PutItem(ctx, &dynamodb.PutItemInput{TableName: aws.String(s.table), Item: r})
	if err != nil {
		return fmt.Errorf("put %s into table %s: %w", what, s.table, err)
	}
	return nil
}

// get reads the item at pk and sk, nil when there is none.
func (s *Store) get(ctx context.Context, pk, sk, what string) (row, error) {
	out, err := s.client.GetItem(ctx, &dynamodb.GetItemInput{
		TableName:      aws.String(s.table),
		Key:            row{"pk": str(pk), "sk": str(sk)},
		ConsistentRead: aws.Bool(true),
	})
	if err != nil {
		return nil, fmt.Errorf("get %s from table %s: %w", what, s.table, err)
	}
	return out.Item, nil
}
