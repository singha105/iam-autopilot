package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	ddbtypes "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"
)

type fakeSSM struct{ name string }

func (f *fakeSSM) GetParameter(_ context.Context, in *ssm.GetParameterInput, _ ...func(*ssm.Options)) (*ssm.GetParameterOutput, error) {
	f.name = aws.ToString(in.Name)
	return &ssm.GetParameterOutput{Parameter: &ssmtypes.Parameter{Value: aws.String(`{"greeting":"hi"}`)}}, nil
}

type fakeDynamo struct {
	getErr error
	putIn  *dynamodb.PutItemInput
}

func (f *fakeDynamo) DescribeTable(context.Context, *dynamodb.DescribeTableInput, ...func(*dynamodb.Options)) (*dynamodb.DescribeTableOutput, error) {
	return &dynamodb.DescribeTableOutput{Table: &ddbtypes.TableDescription{TableStatus: ddbtypes.TableStatusActive}}, nil
}

func (f *fakeDynamo) GetItem(_ context.Context, in *dynamodb.GetItemInput, _ ...func(*dynamodb.Options)) (*dynamodb.GetItemOutput, error) {
	if f.getErr != nil {
		return nil, f.getErr
	}
	return &dynamodb.GetItemOutput{Item: in.Key}, nil
}

func (f *fakeDynamo) PutItem(_ context.Context, in *dynamodb.PutItemInput, _ ...func(*dynamodb.Options)) (*dynamodb.PutItemOutput, error) {
	f.putIn = in
	return &dynamodb.PutItemOutput{}, nil
}

func newTestApp(d *fakeDynamo) (*app, *fakeSSM, *bytes.Buffer) {
	var buf bytes.Buffer
	s := &fakeSSM{}
	return &app{
		ssm:   s,
		ddb:   d,
		param: defaultParam,
		table: defaultTable,
		now:   func() time.Time { return time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC) },
		log:   slog.New(slog.NewJSONHandler(&buf, nil)),
	}, s, &buf
}

func TestHandleReadsConfigAndWritesSettings(t *testing.T) {
	d := &fakeDynamo{}
	a, s, _ := newTestApp(d)

	got, err := a.handle(context.Background())
	if err != nil {
		t.Fatalf("handle: %v", err)
	}
	want := Summary{Config: `{"greeting":"hi"}`, TableStatus: "ACTIVE", ItemFound: true, Written: true}
	if got != want {
		t.Errorf("summary = %+v, want %+v", got, want)
	}
	if s.name != "/iamap/demo/config" {
		t.Errorf("GetParameter name = %q", s.name)
	}
	if aws.ToString(d.putIn.TableName) != "iamap-demo-config" {
		t.Errorf("PutItem table = %q", aws.ToString(d.putIn.TableName))
	}
	pk, ok := d.putIn.Item["pk"].(*ddbtypes.AttributeValueMemberS)
	if !ok || pk.Value != "settings" {
		t.Errorf("PutItem pk = %#v, want S \"settings\"", d.putIn.Item["pk"])
	}
	ts, _ := d.putIn.Item["updatedAt"].(*ddbtypes.AttributeValueMemberS)
	if ts == nil || ts.Value != "2026-09-29T12:00:00Z" {
		t.Errorf("PutItem updatedAt = %#v", d.putIn.Item["updatedAt"])
	}
}

func TestHandleReturnsDataPlaneDenial(t *testing.T) {
	denied := errors.New("AccessDeniedException: not authorized to perform dynamodb:GetItem")
	d := &fakeDynamo{getErr: denied}
	a, _, buf := newTestApp(d)

	_, err := a.handle(context.Background())
	if !errors.Is(err, denied) || !strings.Contains(err.Error(), "dynamodb:GetItem") {
		t.Fatalf("err = %v, want wrapped dynamodb:GetItem denial", err)
	}
	if d.putIn == nil {
		t.Error("PutItem was skipped after GetItem failed")
	}
	var rec map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &rec); err != nil {
		t.Fatalf("want exactly one JSON log line, got %q", buf)
	}
	if rec["action"] != "dynamodb:GetItem" {
		t.Errorf("logged action = %v", rec["action"])
	}
}
