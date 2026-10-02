package store

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	ddbtypes "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

// fakeDB is an in-memory table that evaluates exactly the condition
// expressions the store uses, and pages scans pageSize items at a time.
type fakeDB struct {
	items    map[string]map[string]ddbtypes.AttributeValue
	pageSize int
	scans    int
}

func newFakeDB() *fakeDB { return &fakeDB{items: map[string]map[string]ddbtypes.AttributeValue{}} }

func idOf(k map[string]ddbtypes.AttributeValue) string {
	return k["rolloutId"].(*ddbtypes.AttributeValueMemberS).Value
}

func conditionFailed() error {
	return &ddbtypes.ConditionalCheckFailedException{Message: aws.String("The conditional request failed")}
}

func (f *fakeDB) PutItem(_ context.Context, in *dynamodb.PutItemInput, _ ...func(*dynamodb.Options)) (*dynamodb.PutItemOutput, error) {
	id := idOf(in.Item)
	if aws.ToString(in.ConditionExpression) == "attribute_not_exists(rolloutId)" && f.items[id] != nil {
		return nil, conditionFailed()
	}
	f.items[id] = in.Item
	return &dynamodb.PutItemOutput{}, nil
}

func (f *fakeDB) GetItem(_ context.Context, in *dynamodb.GetItemInput, _ ...func(*dynamodb.Options)) (*dynamodb.GetItemOutput, error) {
	if !aws.ToBool(in.ConsistentRead) {
		return nil, errors.New("test: Get must use a consistent read")
	}
	return &dynamodb.GetItemOutput{Item: f.items[idOf(in.Key)]}, nil
}

func (f *fakeDB) UpdateItem(_ context.Context, in *dynamodb.UpdateItemInput, _ ...func(*dynamodb.Options)) (*dynamodb.UpdateItemOutput, error) {
	id := idOf(in.Key)
	item := f.items[id]
	switch cond := aws.ToString(in.ConditionExpression); cond {
	case "#status = :from":
		if item == nil || item["status"].(*ddbtypes.AttributeValueMemberS).Value != in.ExpressionAttributeValues[":from"].(*ddbtypes.AttributeValueMemberS).Value {
			return nil, conditionFailed()
		}
	case "attribute_exists(rolloutId)":
		if item == nil {
			return nil, conditionFailed()
		}
	default:
		return nil, fmt.Errorf("test: unexpected condition %q", cond)
	}
	for _, set := range strings.Split(strings.TrimPrefix(aws.ToString(in.UpdateExpression), "SET "), ", ") {
		name, val, _ := strings.Cut(set, " = ")
		item[in.ExpressionAttributeNames[name]] = in.ExpressionAttributeValues[val]
	}
	return &dynamodb.UpdateItemOutput{}, nil
}

func (f *fakeDB) Scan(_ context.Context, in *dynamodb.ScanInput, _ ...func(*dynamodb.Options)) (*dynamodb.ScanOutput, error) {
	f.scans++
	var ids []string
	for id := range f.items {
		ids = append(ids, id)
	}
	// Deterministic order for paging.
	for i := range ids {
		for j := i + 1; j < len(ids); j++ {
			if ids[j] < ids[i] {
				ids[i], ids[j] = ids[j], ids[i]
			}
		}
	}
	start := 0
	if in.ExclusiveStartKey != nil {
		last := idOf(in.ExclusiveStartKey)
		for start < len(ids) && ids[start] <= last {
			start++
		}
	}
	end := len(ids)
	if f.pageSize > 0 && start+f.pageSize < end {
		end = start + f.pageSize
	}
	out := &dynamodb.ScanOutput{}
	for _, id := range ids[start:end] {
		item := f.items[id]
		if in.FilterExpression != nil {
			want := in.ExpressionAttributeValues[":r"].(*ddbtypes.AttributeValueMemberS).Value
			if item["roleName"].(*ddbtypes.AttributeValueMemberS).Value != want {
				continue
			}
		}
		out.Items = append(out.Items, item)
	}
	if end < len(ids) {
		out.LastEvaluatedKey = map[string]ddbtypes.AttributeValue{"rolloutId": &ddbtypes.AttributeValueMemberS{Value: ids[end-1]}}
	}
	return out, nil
}

var t0 = time.Date(2026, 10, 2, 5, 0, 0, 0, time.UTC)

func rollout(role string, at time.Time, status Status) Rollout {
	return Rollout{
		RolloutID: NewID(role, at), RoleName: role, RoleArn: "arn:aws:iam::123456789012:role/" + role,
		FunctionName: "fn", PolicyArn: "arn:aws:iam::123456789012:policy/iamap/managed/p",
		Status: status, CurrentVersionID: "v1", ProposedPolicy: `{"Version":"2012-10-17"}`,
		CreatedAt: Timestamp(at), Metrics: Metrics{GrantedBefore: 532, GrantedAfter: 1, RemovedPercent: 99.8, DeniedActions: []string{}},
	}
}

func TestNewID(t *testing.T) {
	if got := NewID("iamap-demo-quarterly-role", t0.Add(7*time.Second)); got != "iamap-demo-quarterly-role-20261002T050007Z" {
		t.Errorf("NewID = %s", got)
	}
}

func TestCreateGetRoundTrip(t *testing.T) {
	db := newFakeDB()
	s := New(db, "")
	r := rollout("role-a", t0, StatusPROpen)
	if err := s.Create(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	// Attribute names are part of the contract.
	item := db.items[r.RolloutID]
	for _, attr := range []string{"rolloutId", "roleName", "roleArn", "functionName", "policyArn", "status", "currentVersionId", "proposedPolicy", "createdAt", "metrics"} {
		if _, ok := item[attr]; !ok {
			t.Errorf("item lacks attribute %q", attr)
		}
	}
	m := item["metrics"].(*ddbtypes.AttributeValueMemberM).Value
	for _, k := range []string{"grantedBefore", "grantedAfter", "removedPercent", "observedActions", "shadowTested", "shadowDenied", "detectSeconds", "rollbackSeconds", "deniedActions"} {
		if _, ok := m[k]; !ok {
			t.Errorf("metrics lacks %q", k)
		}
	}
	if _, ok := item["prUrl"]; ok {
		t.Error("empty optional attributes should be omitted")
	}

	got, err := s.Get(context.Background(), r.RolloutID)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, r) {
		t.Errorf("round trip:\n got %+v\nwant %+v", got, r)
	}
	if err := s.Create(context.Background(), r); !errors.Is(err, ErrExists) {
		t.Errorf("second Create: err = %v, want ErrExists", err)
	}
	if _, err := s.Get(context.Background(), "nope"); !errors.Is(err, ErrNotFound) {
		t.Errorf("Get missing: err = %v", err)
	}
}

func TestUpdateStatusConflict(t *testing.T) {
	db := newFakeDB()
	s := New(db, "")
	r := rollout("role-a", t0, StatusPROpen)
	if err := s.Create(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	// Two processes both read PR_OPEN. The approver wins; cancel must fail.
	if err := s.UpdateStatus(context.Background(), r.RolloutID, StatusPROpen, StatusApproved); err != nil {
		t.Fatalf("first transition: %v", err)
	}
	err := s.UpdateStatus(context.Background(), r.RolloutID, StatusPROpen, StatusCancelled)
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("second transition: err = %v, want ErrConflict", err)
	}
	got, _ := s.Get(context.Background(), r.RolloutID)
	if got.Status != StatusApproved {
		t.Errorf("status = %s, want APPROVED (the loser must not overwrite it)", got.Status)
	}
}

func TestSetFields(t *testing.T) {
	db := newFakeDB()
	s := New(db, "")
	r := rollout("role-a", t0, StatusPROpen)
	if err := s.Create(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	err := s.SetFields(context.Background(), r.RolloutID, map[string]any{
		"prNumber": 7, "prUrl": "https://github.com/o/r/pull/7", "prBranch": "autopilot/" + r.RolloutID,
		"finishedAt": Timestamp(t0.Add(time.Minute)),
		"metrics":    Metrics{ShadowTested: 5, DeniedActions: []string{"ssm:GetParametersByPath"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	got, _ := s.Get(context.Background(), r.RolloutID)
	if got.PRNumber != 7 || got.PRBranch != "autopilot/"+r.RolloutID || got.FinishedAt != "2026-10-02T05:01:00Z" ||
		got.Metrics.ShadowTested != 5 || got.Metrics.DeniedActions[0] != "ssm:GetParametersByPath" || got.Status != StatusPROpen {
		t.Errorf("after SetFields: %+v", got)
	}
	if err := s.SetFields(context.Background(), r.RolloutID, map[string]any{"status": "ENFORCED"}); err == nil {
		t.Error("SetFields must not write status")
	}
	if err := s.SetFields(context.Background(), r.RolloutID, map[string]any{"prUlr": "typo"}); err == nil {
		t.Error("SetFields must reject unknown attributes")
	}
	if err := s.SetFields(context.Background(), "missing", map[string]any{"prNumber": 1}); !errors.Is(err, ErrNotFound) {
		t.Errorf("SetFields on a missing rollout: err = %v", err)
	}
}

func TestPayloadLimit(t *testing.T) {
	s := New(newFakeDB(), "")
	r := rollout("role-a", t0, StatusPROpen)
	r.Summary = strings.Repeat("x", 200*1024)
	r.ShadowReport = strings.Repeat("y", 150*1024)
	if err := s.Create(context.Background(), r); !errors.Is(err, ErrTooLarge) {
		t.Errorf("Create: err = %v, want ErrTooLarge", err)
	}
	r.Summary, r.ShadowReport = "", ""
	if err := s.Create(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	if err := s.SetFields(context.Background(), r.RolloutID, map[string]any{"summary": strings.Repeat("x", 301*1024)}); !errors.Is(err, ErrTooLarge) {
		t.Errorf("SetFields: err = %v, want ErrTooLarge", err)
	}
}

func TestListAllAndActiveForRole(t *testing.T) {
	db := newFakeDB()
	db.pageSize = 2
	s := New(db, "")
	ctx := context.Background()
	for i, st := range []Status{StatusCancelled, StatusEnforced, StatusPROpen, StatusShadowFailed, StatusEnforcedWatching} {
		if err := s.Create(ctx, rollout("role-a", t0.Add(time.Duration(i)*time.Hour), st)); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Create(ctx, rollout("role-b", t0, StatusPROpen)); err != nil {
		t.Fatal(err)
	}

	all, err := s.ListAll(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 6 || db.scans != 3 {
		t.Errorf("ListAll returned %d in %d pages, want 6 in 3", len(all), db.scans)
	}
	if all[0].CreatedAt < all[len(all)-1].CreatedAt {
		t.Error("ListAll should be newest first")
	}

	active, err := s.ActiveForRole(ctx, "role-a")
	if err != nil {
		t.Fatal(err)
	}
	var statuses []Status
	for _, r := range active {
		statuses = append(statuses, r.Status)
	}
	if !reflect.DeepEqual(statuses, []Status{StatusEnforcedWatching, StatusPROpen}) {
		t.Errorf("active statuses = %v", statuses)
	}
}

func TestFinalStates(t *testing.T) {
	final := map[Status]bool{
		StatusObserving: false, StatusPROpen: false, StatusApproved: false, StatusEnforcedWatching: false,
		StatusShadowFailed: true, StatusNothingToDo: true, StatusCancelled: true, StatusEnforced: true, StatusRolledBack: true, StatusFailed: true,
	}
	for s, want := range final {
		if s.Final() != want {
			t.Errorf("%s.Final() = %v", s, s.Final())
		}
	}
}
