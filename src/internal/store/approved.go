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

// Approved is an APPROVED item: the version of a package last approved,
// the check that approved it and its tool-list hash, and the newest
// version a re-check was started for. The poller reads every one, and
// starts a re-check when the package's registry names a version neither
// was.
type Approved struct {
	Kind         string
	Name         string
	Version      string
	CheckID      string
	ToolListHash string
	// Polled is the newest version a re-check was started for: the
	// approved version itself until a newer one is seen.
	Polled string
	// Retry is a version whose re-check failed once and is to be started
	// again (MarkRetry), until the poller starts it (ClearRetry).
	Retry string
}

// approvedPK holds every APPROVED item, so one query reads them all.
const approvedPK = "APPROVED"

// ErrNoApproved says a package has no APPROVED item.
var ErrNoApproved = errors.New("the package has no approved version")

// ErrBadPackage says a package's kind, name or version can't be stored.
var ErrBadPackage = errors.New("a package needs a kind, a name and a version, the kind without a #")

// SplitRef splits a package's pinned ref, name@version, at its last @.
func SplitRef(ref string) (name, version string, ok bool) {
	at := strings.LastIndex(ref, "@")
	if at <= 0 || at == len(ref)-1 {
		return "", "", false
	}
	return ref[:at], ref[at+1:], true
}

// approvedSK is the sort key of a package's APPROVED item.
func approvedSK(kind, name string) (string, error) {
	if kind == "" || name == "" || strings.Contains(kind, "#") {
		return "", ErrBadPackage
	}
	return kind + "#" + name, nil
}

// PutApproved writes a's APPROVED item with Polled set to its version. A
// fresh approval (conditional false) is written whatever was there before.
// A re-check's approval (conditional true) is written only while the
// package's newest polled version — the version the poller started this
// re-check for — is still a's version, or the package has no approval yet.
// So, of several re-checks racing from one approval, only the one for the
// newest version the poller has seen wins, whichever finishes first; an
// older version's late pass, or a re-check overtaken by a newer poll, is a
// no-op, not an overwrite and not an error. The gate is the version, held
// in `polled`, which the poller only ever advances (MarkPolled), not the
// order the re-checks finished in.
func (s *Store) PutApproved(ctx context.Context, a Approved, conditional bool) error {
	sk, err := approvedSK(a.Kind, a.Name)
	if err != nil || a.Version == "" {
		return ErrBadPackage
	}
	a.Polled = a.Version
	in := &dynamodb.PutItemInput{TableName: aws.String(s.table), Item: approvedRow(sk, a)}
	if conditional {
		in.ConditionExpression = aws.String("attribute_not_exists(pk) OR polled = :version")
		in.ExpressionAttributeValues = row{":version": str(a.Version)}
	}
	_, err = s.client.PutItem(ctx, in)
	if failed := new(types.ConditionalCheckFailedException); errors.As(err, &failed) {
		// A newer version has been polled or approved: leave it.
		return nil
	}
	if err != nil {
		return fmt.Errorf("put the approval of %s into table %s: %w", sk, s.table, err)
	}
	return nil
}

// ListApproved reads every APPROVED item.
func (s *Store) ListApproved(ctx context.Context) ([]Approved, error) {
	pages := dynamodb.NewQueryPaginator(s.client, &dynamodb.QueryInput{
		TableName:                 aws.String(s.table),
		KeyConditionExpression:    aws.String("pk = :pk"),
		ExpressionAttributeValues: row{":pk": str(approvedPK)},
	})
	out := []Approved{}
	for pages.HasMorePages() {
		page, err := pages.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("query the approved packages in table %s: %w", s.table, err)
		}
		for _, r := range page.Items {
			a, err := approvedFrom(r)
			if err != nil {
				return nil, fmt.Errorf("read an approved package: %w", err)
			}
			out = append(out, a)
		}
	}
	return out, nil
}

// MarkPolled sets the newest version a re-check of package kind and name
// was started for. Setting it twice changes nothing more; a package with
// no APPROVED item answers ErrNoApproved, without creating one.
func (s *Store) MarkPolled(ctx context.Context, kind, name, version string) error {
	sk, err := approvedSK(kind, name)
	if err != nil || version == "" {
		return ErrBadPackage
	}
	_, err = s.client.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName:                 aws.String(s.table),
		Key:                       row{"pk": str(approvedPK), "sk": str(sk)},
		UpdateExpression:          aws.String("SET #polled = :polled"),
		ConditionExpression:       aws.String("attribute_exists(pk)"),
		ExpressionAttributeNames:  map[string]string{"#polled": "polled"},
		ExpressionAttributeValues: row{":polled": str(version)},
	})
	if failed := new(types.ConditionalCheckFailedException); errors.As(err, &failed) {
		return fmt.Errorf("mark %s polled at %s: %w", sk, version, ErrNoApproved)
	}
	if err != nil {
		return fmt.Errorf("mark %s polled at %s in table %s: %w", sk, version, s.table, err)
	}
	return nil
}

func approvedRow(sk string, a Approved) row {
	return row{
		"pk":           str(approvedPK),
		"sk":           str(sk),
		"kind":         str(a.Kind),
		"name":         str(a.Name),
		"version":      str(a.Version),
		"checkId":      str(a.CheckID),
		"toolListHash": str(a.ToolListHash),
		"polled":       str(a.Polled),
	}
}

func approvedFrom(r row) (Approved, error) {
	var a Approved
	err := readStrs(r, map[string]*string{
		"kind":         &a.Kind,
		"name":         &a.Name,
		"version":      &a.Version,
		"checkId":      &a.CheckID,
		"toolListHash": &a.ToolListHash,
		"polled":       &a.Polled,
	})
	if retry, ok := r["retry"].(*types.AttributeValueMemberS); ok {
		a.Retry = retry.Value
	}
	return a, err
}
