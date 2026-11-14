package store

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

// DynamoAPI is the part of DynamoDB's client the store calls, so a test
// passes a fake without the network.
type DynamoAPI interface {
	GetItem(ctx context.Context, in *dynamodb.GetItemInput, opts ...func(*dynamodb.Options)) (*dynamodb.GetItemOutput, error)
	PutItem(ctx context.Context, in *dynamodb.PutItemInput, opts ...func(*dynamodb.Options)) (*dynamodb.PutItemOutput, error)
	Query(ctx context.Context, in *dynamodb.QueryInput, opts ...func(*dynamodb.Options)) (*dynamodb.QueryOutput, error)
	UpdateItem(ctx context.Context, in *dynamodb.UpdateItemInput, opts ...func(*dynamodb.Options)) (*dynamodb.UpdateItemOutput, error)
	TransactWriteItems(ctx context.Context, in *dynamodb.TransactWriteItemsInput, opts ...func(*dynamodb.Options)) (*dynamodb.TransactWriteItemsOutput, error)
}

// The errors of a check's META that can't be written as asked.
var (
	ErrCheckExists = errors.New("the check already exists")
	ErrNoCheck     = errors.New("there is no such check")
	ErrEmptyUpdate = errors.New("an update must set a status, a verdict, a callback ID, a sandbox ID or a re-check's outcome")
)

// ErrItemTooLarge says an item is larger than DynamoDB keeps, so it was
// not sent.
var ErrItemTooLarge = errors.New("the item is larger than the 400 KB DynamoDB keeps")

// CheckUpdate is what an update of a check's META sets: only the fields
// that aren't empty. The rest of the item stays as it is.
type CheckUpdate struct {
	Status     Status
	Verdict    string
	CallbackID string
	SandboxID  string
	// RecheckFailed marks an approved check with the retry of its re-check
	// that failed again. Its supersededBy is MarkSuperseded's.
	RecheckFailed string
}

// Store keeps checks, their steps and verdicts in one table keyed by pk
// and sk. A check's META is created once and then only updated, field by
// field; every other write puts a whole item. A retried write changes
// nothing twice.
type Store struct {
	client DynamoAPI
	table  string
}

// New returns a store on table, sending through client.
func New(client DynamoAPI, table string) *Store {
	return &Store{client: client, table: table}
}

// PutCheck creates c's META item, only if check c.ID has none: otherwise it
// changes nothing and answers ErrCheckExists, so an older write never
// overwrites a later one. UpdateCheck changes the item after.
func (s *Store) PutCheck(ctx context.Context, c Check) error {
	pk, err := checkPK(c.ID)
	if err != nil {
		return err
	}
	_, err = s.client.PutItem(ctx, &dynamodb.PutItemInput{
		TableName:           aws.String(s.table),
		Item:                checkRow(pk, c),
		ConditionExpression: aws.String("attribute_not_exists(pk)"),
	})
	if failed := new(types.ConditionalCheckFailedException); errors.As(err, &failed) {
		return fmt.Errorf("create check %s: %w", c.ID, ErrCheckExists)
	}
	if err != nil {
		return fmt.Errorf("create check %s in table %s: %w", c.ID, s.table, err)
	}
	return nil
}

// UpdateCheck sets, on check id's META item, the fields of u that aren't
// empty, and leaves every other field as it is. It answers ErrNoCheck when
// the check doesn't exist, without creating it.
func (s *Store) UpdateCheck(ctx context.Context, id string, u CheckUpdate) error {
	pk, err := checkPK(id)
	if err != nil {
		return err
	}
	expr, names, values, err := checkSets(u)
	if err != nil {
		return err
	}
	_, err = s.client.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName:                 aws.String(s.table),
		Key:                       row{"pk": str(pk), "sk": str(metaSK)},
		UpdateExpression:          aws.String(expr),
		ConditionExpression:       aws.String("attribute_exists(pk)"),
		ExpressionAttributeNames:  names,
		ExpressionAttributeValues: values,
	})
	if failed := new(types.ConditionalCheckFailedException); errors.As(err, &failed) {
		return fmt.Errorf("update check %s: %w", id, ErrNoCheck)
	}
	if err != nil {
		return fmt.Errorf("update check %s in table %s: %w", id, s.table, err)
	}
	return nil
}

// checkSets is the update expression, names and values that set u's
// fields that aren't empty, or ErrEmptyUpdate when none is set.
func checkSets(u CheckUpdate) (string, map[string]string, row, error) {
	var sets []string
	names := map[string]string{}
	values := row{}
	for _, field := range []struct{ name, value string }{
		{"status", string(u.Status)},
		{"verdict", u.Verdict},
		{"callbackId", u.CallbackID},
		{"sandboxId", u.SandboxID},
		{"recheckFailed", u.RecheckFailed},
	} {
		if field.value == "" {
			continue
		}
		sets = append(sets, fmt.Sprintf("#%s = :%s", field.name, field.name))
		names["#"+field.name] = field.name
		values[":"+field.name] = str(field.value)
	}
	if len(sets) == 0 {
		return "", nil, nil, ErrEmptyUpdate
	}
	return "SET " + strings.Join(sets, ", "), names, values, nil
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
	if n := itemSize(r); n > MaxItemSize {
		return fmt.Errorf("step %d of check %s is %d bytes: %w", step.Seq, checkID, n, ErrItemTooLarge)
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
