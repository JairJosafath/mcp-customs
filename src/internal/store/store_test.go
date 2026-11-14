package store

import (
	"context"
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
)

// fakeDynamo keeps one table's items in memory, keyed by pk and sk. A query
// answers one item a page, so the store must follow LastEvaluatedKey; err
// makes every call fail, as an outage would.
type fakeDynamo struct {
	items  map[[2]string]row
	tables []string
	err    error
}

func newFakeDynamo() *fakeDynamo { return &fakeDynamo{items: map[[2]string]row{}} }

func keyOf(r row) [2]string {
	pk, _ := readStr(r, "pk")
	sk, _ := readStr(r, "sk")
	return [2]string{pk, sk}
}

func (f *fakeDynamo) GetItem(_ context.Context, in *dynamodb.GetItemInput, _ ...func(*dynamodb.Options)) (*dynamodb.GetItemOutput, error) {
	if f.err != nil {
		return nil, f.err
	}
	f.tables = append(f.tables, aws.ToString(in.TableName))
	return &dynamodb.GetItemOutput{Item: f.items[keyOf(in.Key)]}, nil
}

func (f *fakeDynamo) PutItem(_ context.Context, in *dynamodb.PutItemInput, _ ...func(*dynamodb.Options)) (*dynamodb.PutItemOutput, error) {
	if f.err != nil {
		return nil, f.err
	}
	f.tables = append(f.tables, aws.ToString(in.TableName))
	f.items[keyOf(in.Item)] = in.Item
	return &dynamodb.PutItemOutput{}, nil
}

func (f *fakeDynamo) Query(_ context.Context, in *dynamodb.QueryInput, _ ...func(*dynamodb.Options)) (*dynamodb.QueryOutput, error) {
	if f.err != nil {
		return nil, f.err
	}
	f.tables = append(f.tables, aws.ToString(in.TableName))
	if aws.ToString(in.KeyConditionExpression) != "pk = :pk AND begins_with(sk, :step)" {
		return nil, errors.New("unexpected key condition " + aws.ToString(in.KeyConditionExpression))
	}
	pk, _ := readStr(in.ExpressionAttributeValues, ":pk")
	prefix, _ := readStr(in.ExpressionAttributeValues, ":step")
	after := ""
	if in.ExclusiveStartKey != nil {
		after = keyOf(in.ExclusiveStartKey)[1]
	}
	var sks []string
	for key := range f.items {
		if key[0] == pk && strings.HasPrefix(key[1], prefix) && key[1] > after {
			sks = append(sks, key[1])
		}
	}
	slices.Sort(sks)
	if len(sks) == 0 {
		return &dynamodb.QueryOutput{}, nil
	}
	item := f.items[[2]string{pk, sks[0]}]
	out := &dynamodb.QueryOutput{Items: []row{item}}
	if len(sks) > 1 {
		out.LastEvaluatedKey = row{"pk": str(pk), "sk": str(sks[0])}
	}
	return out, nil
}

func TestStorePutsAndGetsACheck(t *testing.T) {
	for name, want := range map[string]Check{
		"a running check": {ID: "c1", Submission: Submission{Kind: "npm", Ref: "weather-mcp@1.0.0"}, Status: StatusRunning, ExecutionARN: "arn:aws:lambda:us-east-1:111122223333:function:checker:$LATEST/durable-execution/c1/x"},
		"a finished check": {
			ID: "c2", Submission: Submission{Kind: "remote", Ref: "https://mcp.example.com/"},
			Status: StatusDone, Verdict: "block", CallbackID: "cb-1",
		},
	} {
		fake := newFakeDynamo()
		store := New(fake, "customs")
		if err := store.PutCheck(t.Context(), want); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if _, ok := fake.items[[2]string{"CHECK#" + want.ID, "META"}]; !ok {
			t.Errorf("%s: no item at CHECK#%s, META: %v", name, want.ID, fake.items)
		}
		got, found, err := store.GetCheck(t.Context(), want.ID)
		if err != nil || !found || got != want {
			t.Errorf("%s: GetCheck = %+v, %v, %v; want %+v", name, got, found, err, want)
		}
		if !slices.Equal(fake.tables, []string{"customs", "customs"}) {
			t.Errorf("%s: called tables %v, want customs", name, fake.tables)
		}
	}
}

func TestStoreAppendsAndListsStepsInOrder(t *testing.T) {
	for name, tc := range map[string]struct {
		steps []Step
	}{
		"none": {nil},
		"one":  {[]Step{{Seq: 1, Name: "start", Summary: "The check started.", Findings: []Finding{}}}},
		"three, appended out of order": {[]Step{
			{Seq: 10, Name: "probe", Summary: "Probed get_weather.", Findings: []Finding{{Source: "code", Rule: "canary-left", Evidence: "id_ed25519 to 203.0.113.9"}}},
			{Seq: 2, Name: "list", Summary: "Listed 2 tools.", Findings: []Finding{}},
			{Seq: 1, Name: "start", Summary: "The check started.", Findings: []Finding{}},
		}},
	} {
		fake := newFakeDynamo()
		store := New(fake, "customs")
		for _, step := range tc.steps {
			if err := store.AppendStep(t.Context(), "c1", step); err != nil {
				t.Fatalf("%s: %v", name, err)
			}
		}
		// Another check's step and its META are not this check's steps.
		if err := store.AppendStep(t.Context(), "c2", Step{Seq: 1, Name: "other"}); err != nil {
			t.Fatal(err)
		}
		if err := store.PutCheck(t.Context(), Check{ID: "c1", Status: StatusRunning}); err != nil {
			t.Fatal(err)
		}
		got, err := store.ListSteps(t.Context(), "c1")
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		want := slices.SortedFunc(slices.Values(tc.steps), func(a, b Step) int { return a.Seq - b.Seq })
		if want == nil {
			want = []Step{}
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%s: ListSteps = %+v, want %+v", name, got, want)
		}
	}
}

func TestStoreKeepsAStepWithoutFindingsAsAnEmptyList(t *testing.T) {
	fake := newFakeDynamo()
	store := New(fake, "customs")
	if err := store.AppendStep(t.Context(), "c1", Step{Seq: 1, Name: "start"}); err != nil {
		t.Fatal(err)
	}
	findings, _ := readStr(fake.items[[2]string{"CHECK#c1", "STEP#0001"}], "findings")
	if findings != "[]" {
		t.Errorf("findings = %q, want []", findings)
	}
}

func TestStorePutsAndGetsAVerdict(t *testing.T) {
	hash := strings.Repeat("0f", 32)
	want := Verdict{Hash: hash, CheckID: "c1", ToolListHash: strings.Repeat("a", 64), InstallSpec: "npm install mail-mcp@1.0.0"}
	fake := newFakeDynamo()
	store := New(fake, "customs")
	if err := store.PutVerdict(t.Context(), want); err != nil {
		t.Fatal(err)
	}
	if _, ok := fake.items[[2]string{"HASH#" + hash, "VERDICT"}]; !ok {
		t.Errorf("no item at HASH#%s, VERDICT: %v", hash, fake.items)
	}
	got, found, err := store.GetVerdict(t.Context(), hash)
	if err != nil || !found || got != want {
		t.Errorf("GetVerdict = %+v, %v, %v; want %+v", got, found, err, want)
	}
}

func TestStoreAnswersNotFound(t *testing.T) {
	store := New(newFakeDynamo(), "customs")
	if _, found, err := store.GetCheck(t.Context(), "missing"); found || err != nil {
		t.Errorf("GetCheck of a missing check = %v, %v; want false, nil", found, err)
	}
	if _, found, err := store.GetVerdict(t.Context(), strings.Repeat("0", 64)); found || err != nil {
		t.Errorf("GetVerdict of a missing hash = %v, %v; want false, nil", found, err)
	}
}

func TestStoreRefusesBadKeysWithoutCallingDynamoDB(t *testing.T) {
	fake := newFakeDynamo()
	store := New(fake, "customs")
	for name, tc := range map[string]struct {
		call func() error
		want error
	}{
		"put a check":   {func() error { return store.PutCheck(t.Context(), Check{ID: "a b"}) }, ErrBadCheckID},
		"get a check":   {func() error { _, _, err := store.GetCheck(t.Context(), ""); return err }, ErrBadCheckID},
		"append a step": {func() error { return store.AppendStep(t.Context(), "c1", Step{Seq: 0}) }, ErrBadSeq},
		"step of no id": {func() error { return store.AppendStep(t.Context(), "", Step{Seq: 1}) }, ErrBadCheckID},
		"list steps":    {func() error { _, err := store.ListSteps(t.Context(), "#"); return err }, ErrBadCheckID},
		"put a verdict": {func() error { return store.PutVerdict(t.Context(), Verdict{Hash: "abc"}) }, ErrBadHash},
		"get a verdict": {func() error { _, _, err := store.GetVerdict(t.Context(), "ABC"); return err }, ErrBadHash},
	} {
		if err := tc.call(); !errors.Is(err, tc.want) {
			t.Errorf("%s: %v, want %v", name, err, tc.want)
		}
	}
	if len(fake.tables) != 0 {
		t.Errorf("DynamoDB was called %d times", len(fake.tables))
	}
}

func TestStoreWrapsDynamoDBFailures(t *testing.T) {
	outage := errors.New("timeout")
	fake := newFakeDynamo()
	fake.err = outage
	store := New(fake, "customs")
	hash := strings.Repeat("0", 64)
	for name, call := range map[string]func() error{
		"put a check":   func() error { return store.PutCheck(t.Context(), Check{ID: "c1"}) },
		"get a check":   func() error { _, _, err := store.GetCheck(t.Context(), "c1"); return err },
		"append a step": func() error { return store.AppendStep(t.Context(), "c1", Step{Seq: 1}) },
		"list steps":    func() error { _, err := store.ListSteps(t.Context(), "c1"); return err },
		"put a verdict": func() error { return store.PutVerdict(t.Context(), Verdict{Hash: hash}) },
		"get a verdict": func() error { _, _, err := store.GetVerdict(t.Context(), hash); return err },
	} {
		err := call()
		if !errors.Is(err, outage) || !strings.Contains(err.Error(), "customs") {
			t.Errorf("%s: %v, want the outage wrapped with the table", name, err)
		}
	}
}

func TestStoreRefusesMalformedItems(t *testing.T) {
	hash := strings.Repeat("0", 64)
	for name, tc := range map[string]struct {
		key  [2]string
		item row
		call func(*Store) error
	}{
		"a check without a status": {
			[2]string{"CHECK#c1", "META"},
			row{"pk": str("CHECK#c1"), "sk": str("META"), "id": str("c1")},
			func(s *Store) error { _, _, err := s.GetCheck(t.Context(), "c1"); return err },
		},
		"a step whose seq is text": {
			[2]string{"CHECK#c1", "STEP#0001"},
			row{"pk": str("CHECK#c1"), "sk": str("STEP#0001"), "seq": str("1"), "name": str(""), "summary": str(""), "findings": str("[]")},
			func(s *Store) error { _, err := s.ListSteps(t.Context(), "c1"); return err },
		},
		"a step whose findings are not JSON": {
			[2]string{"CHECK#c1", "STEP#0001"},
			row{"pk": str("CHECK#c1"), "sk": str("STEP#0001"), "seq": num(1), "name": str(""), "summary": str(""), "findings": str("{")},
			func(s *Store) error { _, err := s.ListSteps(t.Context(), "c1"); return err },
		},
		"a verdict without its check": {
			[2]string{"HASH#" + hash, "VERDICT"},
			row{"pk": str("HASH#" + hash), "sk": str("VERDICT"), "hash": str(hash)},
			func(s *Store) error { _, _, err := s.GetVerdict(t.Context(), hash); return err },
		},
	} {
		fake := newFakeDynamo()
		fake.items[tc.key] = tc.item
		if err := tc.call(New(fake, "customs")); !errors.Is(err, errMalformed) {
			t.Errorf("%s: %v, want a malformed item", name, err)
		}
	}
}
