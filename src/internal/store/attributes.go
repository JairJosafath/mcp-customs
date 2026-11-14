package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"

	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

// row is one item as DynamoDB holds it.
type row = map[string]types.AttributeValue

// errMalformed says an item in the table isn't what the store writes.
var errMalformed = errors.New("malformed item")

func str(value string) types.AttributeValue { return &types.AttributeValueMemberS{Value: value} }

func num(value int) types.AttributeValue {
	return &types.AttributeValueMemberN{Value: strconv.Itoa(value)}
}

// readStr reads the string attribute name of r.
func readStr(r row, name string) (string, error) {
	value, ok := r[name].(*types.AttributeValueMemberS)
	if !ok {
		return "", fmt.Errorf("%w: %q is not a string", errMalformed, name)
	}
	return value.Value, nil
}

// readStrs reads the string attributes names of r into the fields they point to.
func readStrs(r row, fields map[string]*string) error {
	for name, field := range fields {
		value, err := readStr(r, name)
		if err != nil {
			return err
		}
		*field = value
	}
	return nil
}

func checkRow(pk string, c Check) row {
	return row{
		"pk":             str(pk),
		"sk":             str(metaSK),
		"id":             str(c.ID),
		"submissionKind": str(c.Submission.Kind),
		"submissionRef":  str(c.Submission.Ref),
		"status":         str(string(c.Status)),
		"verdict":        str(c.Verdict),
		"executionArn":   str(c.ExecutionARN),
		"callbackId":     str(c.CallbackID),
	}
}

func checkFrom(r row) (Check, error) {
	var c Check
	var status string
	err := readStrs(r, map[string]*string{
		"id":             &c.ID,
		"submissionKind": &c.Submission.Kind,
		"submissionRef":  &c.Submission.Ref,
		"status":         &status,
		"verdict":        &c.Verdict,
		"executionArn":   &c.ExecutionARN,
		"callbackId":     &c.CallbackID,
	})
	c.Status = Status(status)
	return c, err
}

func stepRow(pk, sk string, s Step) (row, error) {
	findings := s.Findings
	if findings == nil {
		findings = []Finding{}
	}
	encoded, err := json.Marshal(findings)
	if err != nil {
		return nil, fmt.Errorf("encode the findings of step %d: %w", s.Seq, err)
	}
	return row{
		"pk":       str(pk),
		"sk":       str(sk),
		"seq":      num(s.Seq),
		"name":     str(s.Name),
		"summary":  str(s.Summary),
		"findings": str(string(encoded)),
	}, nil
}

func stepFrom(r row) (Step, error) {
	var s Step
	var findings string
	if err := readStrs(r, map[string]*string{"name": &s.Name, "summary": &s.Summary, "findings": &findings}); err != nil {
		return Step{}, err
	}
	seq, ok := r["seq"].(*types.AttributeValueMemberN)
	if !ok {
		return Step{}, fmt.Errorf(`%w: "seq" is not a number`, errMalformed)
	}
	n, err := strconv.Atoi(seq.Value)
	if err != nil {
		return Step{}, fmt.Errorf(`%w: "seq" is not an integer: %w`, errMalformed, err)
	}
	s.Seq = n
	if err := json.Unmarshal([]byte(findings), &s.Findings); err != nil {
		return Step{}, fmt.Errorf(`%w: "findings" is not JSON: %w`, errMalformed, err)
	}
	return s, nil
}

func verdictRow(pk string, v Verdict) row {
	return row{
		"pk":           str(pk),
		"sk":           str(verdictSK),
		"hash":         str(v.Hash),
		"checkId":      str(v.CheckID),
		"toolListHash": str(v.ToolListHash),
		"installSpec":  str(v.InstallSpec),
	}
}

func verdictFrom(r row) (Verdict, error) {
	var v Verdict
	err := readStrs(r, map[string]*string{
		"hash":         &v.Hash,
		"checkId":      &v.CheckID,
		"toolListHash": &v.ToolListHash,
		"installSpec":  &v.InstallSpec,
	})
	return v, err
}
