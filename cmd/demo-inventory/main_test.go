package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	awslambda "github.com/aws/aws-sdk-go-v2/service/lambda"
	lambdatypes "github.com/aws/aws-sdk-go-v2/service/lambda/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
)

type fakeEC2 struct {
	regionsErr   error
	instancesIn  *ec2.DescribeInstancesInput
	instancesErr error
}

func (f *fakeEC2) DescribeRegions(context.Context, *ec2.DescribeRegionsInput, ...func(*ec2.Options)) (*ec2.DescribeRegionsOutput, error) {
	if f.regionsErr != nil {
		return nil, f.regionsErr
	}
	return &ec2.DescribeRegionsOutput{Regions: make([]ec2types.Region, 17)}, nil
}

func (f *fakeEC2) DescribeInstances(_ context.Context, in *ec2.DescribeInstancesInput, _ ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error) {
	f.instancesIn = in
	if f.instancesErr != nil {
		return nil, f.instancesErr
	}
	return &ec2.DescribeInstancesOutput{Reservations: []ec2types.Reservation{
		{Instances: make([]ec2types.Instance, 2)},
		{Instances: make([]ec2types.Instance, 1)},
	}}, nil
}

type fakeS3 struct{ err error }

func (f fakeS3) ListBuckets(context.Context, *s3.ListBucketsInput, ...func(*s3.Options)) (*s3.ListBucketsOutput, error) {
	if f.err != nil {
		return nil, f.err
	}
	return &s3.ListBucketsOutput{Buckets: make([]s3types.Bucket, 4)}, nil
}

type fakeLambda struct{ in *awslambda.ListFunctionsInput }

func (f *fakeLambda) ListFunctions(_ context.Context, in *awslambda.ListFunctionsInput, _ ...func(*awslambda.Options)) (*awslambda.ListFunctionsOutput, error) {
	f.in = in
	return &awslambda.ListFunctionsOutput{Functions: make([]lambdatypes.FunctionConfiguration, 5)}, nil
}

type fakeIAM struct{ in *iam.ListRolesInput }

func (f *fakeIAM) ListRoles(_ context.Context, in *iam.ListRolesInput, _ ...func(*iam.Options)) (*iam.ListRolesOutput, error) {
	f.in = in
	return &iam.ListRolesOutput{Roles: make([]iamtypes.Role, 5)}, nil
}

func newTestApp(e *fakeEC2, s fakeS3) (*app, *fakeLambda, *fakeIAM, *bytes.Buffer) {
	var buf bytes.Buffer
	l, i := &fakeLambda{}, &fakeIAM{}
	return &app{ec2: e, s3: s, lambda: l, iam: i, log: slog.New(slog.NewJSONHandler(&buf, nil))}, l, i, &buf
}

func TestHandleSummarisesAllCalls(t *testing.T) {
	e := &fakeEC2{}
	a, l, i, _ := newTestApp(e, fakeS3{})

	got, err := a.handle(context.Background())
	if err != nil {
		t.Fatalf("handle: %v", err)
	}
	want := Summary{Regions: 17, Instances: 3, Buckets: 4, Functions: 5, Roles: 5}
	if got != want {
		t.Errorf("summary = %+v, want %+v", got, want)
	}
	if aws.ToInt32(e.instancesIn.MaxResults) != 5 {
		t.Errorf("DescribeInstances MaxResults = %d, want 5", aws.ToInt32(e.instancesIn.MaxResults))
	}
	if aws.ToInt32(l.in.MaxItems) != 5 || aws.ToInt32(i.in.MaxItems) != 5 {
		t.Errorf("ListFunctions/ListRoles MaxItems = %d/%d, want 5/5", aws.ToInt32(l.in.MaxItems), aws.ToInt32(i.in.MaxItems))
	}
}

func TestHandleReturnsAndLogsEveryError(t *testing.T) {
	denied := errors.New("AccessDenied: not authorized")
	a, _, _, buf := newTestApp(&fakeEC2{instancesErr: denied}, fakeS3{err: denied})

	got, err := a.handle(context.Background())
	if err == nil {
		t.Fatal("handle returned nil error, want the AWS errors")
	}
	if !errors.Is(err, denied) {
		t.Errorf("error %v does not wrap the AWS error", err)
	}
	for _, action := range []string{"ec2:DescribeInstances", "s3:ListBuckets"} {
		if !strings.Contains(err.Error(), action) {
			t.Errorf("error %q does not name %s", err, action)
		}
	}
	// Calls after a failure still run.
	if got.Functions != 5 || got.Roles != 5 {
		t.Errorf("later calls skipped after failure: %+v", got)
	}

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("got %d log lines, want 2 (one per error):\n%s", len(lines), buf)
	}
	for _, line := range lines {
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("log line is not JSON: %q", line)
		}
		if rec["level"] != "ERROR" || rec["app"] != appName || rec["action"] == nil {
			t.Errorf("unexpected log record %v", rec)
		}
	}
}
