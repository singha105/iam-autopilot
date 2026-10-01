package observe

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	cttypes "github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/smithy-go"
)

func day(n int) time.Duration { return time.Duration(n) * 24 * time.Hour }

func TestCollectAggregatesCalls(t *testing.T) {
	t1, t2, t3 := testNow.Add(-3*time.Hour), testNow.Add(-2*time.Hour), testNow.Add(-time.Hour)
	ct := &fakeCloudTrail{pages: [][]cttypes.Event{{
		ev{source: "ssm.amazonaws.com", name: "GetParameter", at: t2, params: map[string]any{"name": "/iamap/demo/config"}}.event(t),
		ev{source: "ssm.amazonaws.com", name: "GetParameter", at: t1, params: map[string]any{"name": "/iamap/demo/config"}}.event(t),
		ev{source: "ssm.amazonaws.com", name: "GetParameter", at: t3, params: map[string]any{"name": "/iamap/demo/config"}}.event(t),
		ev{source: "s3.amazonaws.com", name: "ListBuckets", at: t1}.event(t),
	}}}
	o, _ := testObserver(ct, nil)

	calls, denied, err := o.CollectEvents(context.Background(), testRole, testNow.Add(-day(1)), testNow)
	if err != nil {
		t.Fatal(err)
	}
	if len(denied) != 0 {
		t.Errorf("denied = %v, want none", denied)
	}
	want := []ObservedCall{
		{Action: "s3:ListAllMyBuckets", Resource: "*", Count: 1, FirstSeen: t1, LastSeen: t1, ReadOnly: true},
		{Action: "ssm:GetParameter", Resource: "arn:aws:ssm:us-east-1:123456789012:parameter/iamap/demo/config", Count: 3, FirstSeen: t1, LastSeen: t3, ReadOnly: true},
	}
	if !reflect.DeepEqual(calls, want) {
		t.Errorf("calls =\n%+v\nwant\n%+v", calls, want)
	}
}

func TestCollectLookupInput(t *testing.T) {
	ct := &fakeCloudTrail{pages: [][]cttypes.Event{{}}}
	o, _ := testObserver(ct, nil)
	if _, err := o.Collect(context.Background(), testRole, testNow.Add(-day(1)), testNow); err != nil {
		t.Fatal(err)
	}
	in := ct.inputs[0]
	if len(in.LookupAttributes) != 1 || in.LookupAttributes[0].AttributeKey != cttypes.LookupAttributeKeyUsername ||
		aws.ToString(in.LookupAttributes[0].AttributeValue) != testFunction {
		t.Errorf("LookupAttributes = %+v, want Username=%s", in.LookupAttributes, testFunction)
	}
	if aws.ToInt32(in.MaxResults) != 50 {
		t.Errorf("MaxResults = %d, want 50", aws.ToInt32(in.MaxResults))
	}
	if !in.StartTime.Equal(testNow.Add(-day(1))) || !in.EndTime.Equal(testNow) {
		t.Errorf("window = %v..%v", in.StartTime, in.EndTime)
	}
}

func TestCollectFollowsNextToken(t *testing.T) {
	ct := &fakeCloudTrail{pages: [][]cttypes.Event{
		{ev{source: "iam.amazonaws.com", name: "ListRoles"}.event(t)},
		{ev{source: "iam.amazonaws.com", name: "ListRoles"}.event(t)},
		{ev{source: "ec2.amazonaws.com", name: "DescribeRegions"}.event(t)},
	}}
	o, _ := testObserver(ct, nil)
	res, err := o.Collect(context.Background(), testRole, testNow.Add(-day(1)), testNow)
	if err != nil {
		t.Fatal(err)
	}
	if res.Stats != (Stats{EventsScanned: 3, PagesFetched: 3}) {
		t.Errorf("stats = %+v", res.Stats)
	}
	if len(ct.inputs) != 3 || ct.inputs[0].NextToken != nil || aws.ToString(ct.inputs[2].NextToken) != "2" {
		t.Errorf("NextToken not followed: %d calls", len(ct.inputs))
	}
	if len(res.Calls) != 2 || res.Calls[1].Action != "iam:ListRoles" || res.Calls[1].Count != 2 {
		t.Errorf("calls = %+v", res.Calls)
	}
}

func TestCollectIgnoresOtherSessionIssuers(t *testing.T) {
	other := "arn:aws:iam::123456789012:role/someone-else"
	ct := &fakeCloudTrail{pages: [][]cttypes.Event{{
		ev{source: "iam.amazonaws.com", name: "ListRoles"}.event(t),
		// Same username, different role: must be ignored.
		ev{issuer: other, source: "iam.amazonaws.com", name: "DeleteRole"}.event(t),
		ev{issuer: other, source: "s3.amazonaws.com", name: "ListBuckets"}.event(t),
	}}}
	o, _ := testObserver(ct, nil)
	res, err := o.Collect(context.Background(), testRole, testNow.Add(-day(1)), testNow)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Calls) != 1 || res.Calls[0].Action != "iam:ListRoles" {
		t.Errorf("calls = %+v, want only iam:ListRoles", res.Calls)
	}
	if res.Stats.EventsScanned != 3 {
		t.Errorf("EventsScanned = %d, want 3", res.Stats.EventsScanned)
	}
	if !containsSubstring(res.Warnings, "ignored 2 event(s)") {
		t.Errorf("warnings = %v, want the ignored-events warning", res.Warnings)
	}
}

func TestCollectExcludesPlatformCalls(t *testing.T) {
	lambdaEnv := map[string]any{"encryptionContext": map[string]any{"aws:lambda:FunctionArn": "arn:aws:lambda:us-east-1:123456789012:function:iamap-demo-inventory"}}
	javaSDK := "aws-sdk-java/2.55.2 api/KMS#2.55.x"
	ct := &fakeCloudTrail{pages: [][]cttypes.Event{{
		// A service calling downstream for the role (invokedBy).
		ev{source: "kms.amazonaws.com", name: "Decrypt", invokedBy: "lambda.amazonaws.com", params: lambdaEnv}.event(t),
		ev{source: "kms.amazonaws.com", name: "Decrypt", invokedBy: "lambda.amazonaws.com", params: lambdaEnv}.event(t),
		// The Lambda runtime at cold start: no invokedBy.
		ev{source: "logs.amazonaws.com", name: "CreateLogStream", userAgent: "awslambda-worker/1.0", params: map[string]any{"logGroupName": "/aws/lambda/iamap-demo-inventory"}}.event(t),
		ev{source: "kms.amazonaws.com", name: "Decrypt", userAgent: javaSDK, params: lambdaEnv}.event(t),
		// The function's own calls are kept, including its own kms:Decrypt.
		ev{source: "iam.amazonaws.com", name: "ListRoles", userAgent: "aws-sdk-go-v2/1.47.1"}.event(t),
		ev{source: "kms.amazonaws.com", name: "Decrypt", userAgent: "aws-sdk-go-v2/1.47.1", params: map[string]any{"encryptionContext": map[string]any{"app": "x"}}}.event(t),
	}}}
	o, _ := testObserver(ct, nil)
	res, err := o.Collect(context.Background(), testRole, testNow.Add(-day(1)), testNow)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, c := range res.Calls {
		got = append(got, c.Action)
	}
	if want := []string{"iam:ListRoles", "kms:Decrypt"}; !reflect.DeepEqual(got, want) {
		t.Errorf("actions = %v, want %v", got, want)
	}
	for _, want := range []string{
		"excluded 2 platform call(s): kms:Decrypt by lambda.amazonaws.com",
		"excluded 1 platform call(s): logs:CreateLogStream by the Lambda runtime (awslambda-worker)",
		"excluded 1 platform call(s): kms:Decrypt by the Lambda runtime (environment variable decryption)",
	} {
		if !containsSubstring(res.Warnings, want) {
			t.Errorf("warnings = %v, want %q", res.Warnings, want)
		}
	}
}

func TestCollectClassifiesDenials(t *testing.T) {
	at := testNow.Add(-time.Hour)
	ct := &fakeCloudTrail{pages: [][]cttypes.Event{{
		ev{source: "ssm.amazonaws.com", name: "GetParametersByPath", at: at, errorCode: "AccessDenied", params: map[string]any{"path": "/iamap/demo/quarterly/"}}.event(t),
		ev{source: "ec2.amazonaws.com", name: "DescribeInstances", at: at, errorCode: "Client.UnauthorizedOperation"}.event(t),
		ev{source: "sns.amazonaws.com", name: "Publish", at: at, errorCode: "AuthorizationError"}.event(t),
		// Authorized but failed: still usage.
		ev{source: "ssm.amazonaws.com", name: "GetParameter", at: at, errorCode: "ParameterNotFound", params: map[string]any{"name": "/missing"}}.event(t),
	}}}
	o, _ := testObserver(ct, nil)
	calls, denied, err := o.CollectEvents(context.Background(), testRole, testNow.Add(-day(1)), testNow)
	if err != nil {
		t.Fatal(err)
	}
	wantDenied := []DeniedCall{
		{Action: "ec2:DescribeInstances", Resource: "*", ErrorCode: "Client.UnauthorizedOperation", Time: at},
		{Action: "sns:Publish", Resource: "*", ErrorCode: "AuthorizationError", Time: at},
		{Action: "ssm:GetParametersByPath", Resource: "arn:aws:ssm:us-east-1:123456789012:parameter/iamap/demo/quarterly", ErrorCode: "AccessDenied", Time: at},
	}
	if !reflect.DeepEqual(denied, wantDenied) {
		t.Errorf("denied =\n%+v\nwant\n%+v", denied, wantDenied)
	}
	if len(calls) != 1 || calls[0].Action != "ssm:GetParameter" {
		t.Errorf("calls = %+v, want the ParameterNotFound call counted as usage", calls)
	}
}

func TestCollectRetriesThrottling(t *testing.T) {
	throttled := &smithy.GenericAPIError{Code: "ThrottlingException", Message: "Rate exceeded"}
	ct := &fakeCloudTrail{
		errs:  []error{throttled, throttled},
		pages: [][]cttypes.Event{{ev{source: "iam.amazonaws.com", name: "ListRoles"}.event(t)}},
	}
	o, slept := testObserver(ct, nil)
	res, err := o.Collect(context.Background(), testRole, testNow.Add(-day(1)), testNow)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(ct.inputs) != 3 {
		t.Errorf("LookupEvents calls = %d, want 3 (2 throttled + 1 success)", len(ct.inputs))
	}
	if want := []time.Duration{500 * time.Millisecond, time.Second}; !reflect.DeepEqual(*slept, want) {
		t.Errorf("backoff = %v, want %v", *slept, want)
	}
	if res.Stats.PagesFetched != 1 || len(res.Calls) != 1 {
		t.Errorf("stats = %+v calls = %+v", res.Stats, res.Calls)
	}
}

func TestCollectGivesUpAfterFiveThrottles(t *testing.T) {
	throttled := &smithy.GenericAPIError{Code: "ThrottlingException"}
	ct := &fakeCloudTrail{errs: []error{throttled, throttled, throttled, throttled, throttled, throttled}}
	o, slept := testObserver(ct, nil)
	_, err := o.Collect(context.Background(), testRole, testNow.Add(-day(1)), testNow)
	if !errors.Is(err, throttled) {
		t.Fatalf("err = %v, want the throttling error", err)
	}
	if len(ct.inputs) != 5 || len(*slept) != 4 {
		t.Errorf("calls = %d sleeps = %d, want 5 and 4", len(ct.inputs), len(*slept))
	}
}

func TestCollectDoesNotRetryOtherErrors(t *testing.T) {
	boom := &smithy.GenericAPIError{Code: "AccessDeniedException"}
	ct := &fakeCloudTrail{errs: []error{boom}}
	o, _ := testObserver(ct, nil)
	if _, err := o.Collect(context.Background(), testRole, testNow.Add(-day(1)), testNow); !errors.Is(err, boom) {
		t.Fatalf("err = %v", err)
	}
	if len(ct.inputs) != 1 {
		t.Errorf("calls = %d, want 1", len(ct.inputs))
	}
}

func TestClampWindow(t *testing.T) {
	o, _ := testObserver(nil, nil)
	tests := []struct {
		name               string
		start, end         time.Time
		wantStart, wantEnd time.Time
		wantWarning        bool
		wantErr            bool
	}{
		{"inside 90 days", testNow.Add(-day(7)), testNow, testNow.Add(-day(7)), testNow, false, false},
		{"start older than 90 days", testNow.Add(-day(200)), testNow, testNow.Add(-day(90)), testNow, true, false},
		{"end in the future", testNow.Add(-day(1)), testNow.Add(day(5)), testNow.Add(-day(1)), testNow, false, false},
		{"zero end means now", testNow.Add(-day(1)), time.Time{}, testNow.Add(-day(1)), testNow, false, false},
		{"sub-second precision dropped", testNow.Add(-day(1) - 300*time.Millisecond), testNow, testNow.Add(-day(1) - time.Second), testNow, false, false},
		{"empty window", testNow, testNow, time.Time{}, time.Time{}, false, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w, warnings, err := o.clampWindow(tt.start, tt.end)
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if !w.Start.Equal(tt.wantStart) || !w.End.Equal(tt.wantEnd) {
				t.Errorf("window = %s..%s, want %s..%s", w.Start, w.End, tt.wantStart, tt.wantEnd)
			}
			if (len(warnings) > 0) != tt.wantWarning {
				t.Errorf("warnings = %v, want warning: %v", warnings, tt.wantWarning)
			}
		})
	}
}

func TestCollectClampsLookupStartTo90Days(t *testing.T) {
	ct := &fakeCloudTrail{pages: [][]cttypes.Event{{}}}
	o, _ := testObserver(ct, nil)
	res, err := o.Collect(context.Background(), testRole, testNow.Add(-day(365)), testNow)
	if err != nil {
		t.Fatal(err)
	}
	if got := *ct.inputs[0].StartTime; !got.Equal(testNow.Add(-day(90))) {
		t.Errorf("LookupEvents StartTime = %s, want now-90d", got)
	}
	if !containsSubstring(res.Warnings, "clamped to 90 days") {
		t.Errorf("warnings = %v", res.Warnings)
	}
}

func TestResolveRole(t *testing.T) {
	roleOut := &iam.GetRoleOutput{Role: &iamtypes.Role{RoleName: aws.String("r"), Arn: aws.String("arn:aws:iam::123456789012:role/r")}}
	tag := func(k, v string) iamtypes.Tag { return iamtypes.Tag{Key: aws.String(k), Value: aws.String(v)} }

	t.Run("managed role with tags over two pages", func(t *testing.T) {
		f := &fakeIAM{role: roleOut, tagPages: []*iam.ListRoleTagsOutput{
			{Tags: []iamtypes.Tag{tag("Project", "iam-autopilot"), tag(TagManaged, "true")}, IsTruncated: true, Marker: aws.String("m")},
			{Tags: []iamtypes.Tag{tag(TagFunction, "fn")}},
		}}
		o, _ := testObserver(nil, f)
		got, err := o.ResolveRole(context.Background(), "r")
		if err != nil {
			t.Fatal(err)
		}
		if got.ARN != "arn:aws:iam::123456789012:role/r" || got.FunctionName != "fn" || got.Name != "r" || f.tagCalls != 2 {
			t.Errorf("role = %+v, tag calls = %d", got, f.tagCalls)
		}
	})

	for name, tags := range map[string][]iamtypes.Tag{
		"untagged role":     nil,
		"managed=false":     {tag(TagManaged, "false"), tag(TagFunction, "fn")},
		"managed=True case": {tag(TagManaged, "True"), tag(TagFunction, "fn")},
	} {
		t.Run("refuses "+name, func(t *testing.T) {
			f := &fakeIAM{role: roleOut, tagPages: []*iam.ListRoleTagsOutput{{Tags: tags}}}
			o, _ := testObserver(nil, f)
			_, err := o.ResolveRole(context.Background(), "r")
			if !errors.Is(err, ErrNotManaged) {
				t.Fatalf("err = %v, want ErrNotManaged", err)
			}
		})
	}

	t.Run("managed role without function tag", func(t *testing.T) {
		f := &fakeIAM{role: roleOut, tagPages: []*iam.ListRoleTagsOutput{{Tags: []iamtypes.Tag{tag(TagManaged, "true")}}}}
		o, _ := testObserver(nil, f)
		_, err := o.ResolveRole(context.Background(), "r")
		if err == nil || !strings.Contains(err.Error(), TagFunction) {
			t.Fatalf("err = %v, want missing function tag error", err)
		}
	})
}

func containsSubstring(list []string, sub string) bool {
	for _, s := range list {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}
