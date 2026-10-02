package shadow

import (
	"context"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"golang.org/x/time/rate"

	"github.com/singha105/iam-autopilot/internal/catalog"
	"github.com/singha105/iam-autopilot/internal/observe"
	"github.com/singha105/iam-autopilot/internal/policy"
)

const (
	paramARN = "arn:aws:ssm:us-east-1:123456789012:parameter/app/config"
	tableARN = "arn:aws:dynamodb:us-east-1:123456789012:table/app-table"
)

var (
	now    = time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	inside = now.Add(-time.Hour)
)

// fakeSimulator evaluates the policy it is given (Allow statements, wildcard
// actions and resources), can force a decision for one action, and pages its
// results pageSize at a time.
type fakeSimulator struct {
	force    map[string]string // action -> decision
	pageSize int
	requests []iam.SimulateCustomPolicyInput
}

func (f *fakeSimulator) SimulateCustomPolicy(_ context.Context, in *iam.SimulateCustomPolicyInput, _ ...func(*iam.Options)) (*iam.SimulateCustomPolicyOutput, error) {
	f.requests = append(f.requests, *in)
	doc, err := policy.Parse([]byte(in.PolicyInputList[0]))
	if err != nil {
		return nil, err
	}
	var all []iamtypes.EvaluationResult
	for _, a := range in.ActionNames {
		decision := iamtypes.PolicyEvaluationDecisionTypeImplicitDeny
		for _, s := range doc.Statement {
			if s.Effect != "Allow" || !anyMatch(s.Action, a) || !anyMatch(s.Resource, in.ResourceArns[0]) {
				continue
			}
			decision = iamtypes.PolicyEvaluationDecisionTypeAllowed
		}
		if d, ok := f.force[a]; ok {
			decision = iamtypes.PolicyEvaluationDecisionType(d)
		}
		all = append(all, iamtypes.EvaluationResult{EvalActionName: aws.String(a), EvalResourceName: aws.String(in.ResourceArns[0]), EvalDecision: decision})
	}
	start := 0
	if in.Marker != nil {
		start, _ = strconv.Atoi(*in.Marker)
	}
	end := len(all)
	if f.pageSize > 0 && start+f.pageSize < end {
		end = start + f.pageSize
	}
	out := &iam.SimulateCustomPolicyOutput{EvaluationResults: all[start:end]}
	if end < len(all) {
		out.IsTruncated, out.Marker = true, aws.String(strconv.Itoa(end))
	}
	return out, nil
}

func anyMatch(patterns []string, s string) bool {
	for _, p := range patterns {
		if p == "*" || catalog.Matches(p, s) {
			return true
		}
	}
	return false
}

func replayer(f *fakeSimulator) *Replayer {
	return &Replayer{IAM: f, Limiter: rate.NewLimiter(rate.Inf, 1)}
}

func profile() observe.Profile {
	t := inside
	return observe.Profile{
		Window: observe.Window{Start: now.Add(-24 * time.Hour), End: now},
		ObservedCalls: []observe.ObservedCall{
			{Action: "ssm:GetParameter", Resource: paramARN},
			{Action: "dynamodb:DescribeTable", Resource: tableARN},
			{Action: "s3:ListAllMyBuckets", Resource: "*"},
		},
		ServicesAccessed: []observe.ServiceAccess{
			{Namespace: "ec2", LastAuthenticated: &t, TrackedActions: []observe.TrackedAction{
				{Action: "ec2:DescribeRegions", LastAccessed: inside},
				{Action: "ec2:DescribeVpcs", LastAccessed: now.Add(-72 * time.Hour)}, // outside the window
			}},
			{Namespace: "logs", LastAuthenticated: &t, TrackedActions: []observe.TrackedAction{{Action: "logs:CreateLogStream", LastAccessed: inside}}},
		},
		ExcludedCalls: []observe.ExcludedCall{{Action: "logs:CreateLogStream", Caller: "the Lambda runtime (awslambda-worker)", Count: 3}},
	}
}

func proposal(t *testing.T, js string) policy.Document {
	t.Helper()
	d, err := policy.Parse([]byte(js))
	if err != nil {
		t.Fatal(err)
	}
	return d
}

const goodProposal = `{"Version":"2012-10-17","Statement":[
 {"Sid":"Dynamodb0","Effect":"Allow","Action":["dynamodb:DescribeTable"],"Resource":["` + tableARN + `"]},
 {"Sid":"Ec20","Effect":"Allow","Action":["ec2:DescribeRegions"],"Resource":["*"]},
 {"Sid":"S30","Effect":"Allow","Action":["s3:ListAllMyBuckets"],"Resource":["*"]},
 {"Sid":"Ssm0","Effect":"Allow","Action":["ssm:GetParameter"],"Resource":["` + paramARN + `"]}]}`

func TestTestSet(t *testing.T) {
	calls, skipped := TestSet(profile())
	want := []Call{
		{Action: "ec2:DescribeRegions", Resource: "*"},
		{Action: "s3:ListAllMyBuckets", Resource: "*"},
		{Action: "dynamodb:DescribeTable", Resource: tableARN},
		{Action: "ssm:GetParameter", Resource: paramARN},
	}
	if !reflect.DeepEqual(calls, want) {
		t.Errorf("test set = %+v\nwant %+v", calls, want)
	}
	if !reflect.DeepEqual(skipped, []string{"logs:CreateLogStream"}) {
		t.Errorf("skipped = %v, want the platform-only action", skipped)
	}
}

func TestReplayAllowsEverything(t *testing.T) {
	f := &fakeSimulator{}
	rep, err := replayer(f).Replay(context.Background(), proposal(t, goodProposal), profile())
	if err != nil {
		t.Fatal(err)
	}
	if rep.Tested != 4 || rep.Allowed != 4 || len(rep.Denied) != 0 {
		t.Errorf("report = %+v", rep)
	}
	// Grouped by resource: one request per distinct resource, several actions each.
	if len(f.requests) != 3 {
		t.Errorf("requests = %d, want 3 (one per resource)", len(f.requests))
	}
	for _, in := range f.requests {
		if len(in.ResourceArns) != 1 || len(in.PolicyInputList) != 1 {
			t.Errorf("request = %+v", in)
		}
		if in.ResourceArns[0] == "*" && len(in.ActionNames) != 2 {
			t.Errorf("* request carries %v, want both * actions", in.ActionNames)
		}
	}
}

func TestReplayReportsExactlyTheDeniedAction(t *testing.T) {
	f := &fakeSimulator{force: map[string]string{"ec2:DescribeRegions": "implicitDeny"}}
	rep, err := replayer(f).Replay(context.Background(), proposal(t, goodProposal), profile())
	if err != nil {
		t.Fatal(err)
	}
	want := []Denial{{Action: "ec2:DescribeRegions", Resource: "*", Decision: "implicitDeny"}}
	if !reflect.DeepEqual(rep.Denied, want) || rep.Allowed != 3 {
		t.Errorf("denied = %+v allowed = %d", rep.Denied, rep.Allowed)
	}
}

func TestReplayCatchesARealGap(t *testing.T) {
	// The proposal forgot ssm:GetParameter: the simulator denies it.
	gap := strings.Replace(goodProposal, `"ssm:GetParameter"`, `"ssm:GetParametersByPath"`, 1)
	rep, err := replayer(&fakeSimulator{}).Replay(context.Background(), proposal(t, gap), profile())
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Denied) != 1 || rep.Denied[0].Action != "ssm:GetParameter" || rep.Denied[0].Resource != paramARN {
		t.Errorf("denied = %+v", rep.Denied)
	}
}

func TestReplayFollowsMarker(t *testing.T) {
	f := &fakeSimulator{pageSize: 1}
	rep, err := replayer(f).Replay(context.Background(), proposal(t, goodProposal), profile())
	if err != nil {
		t.Fatal(err)
	}
	if rep.Tested != 4 || len(f.requests) != 4 { // the * group needs 2 pages
		t.Errorf("tested %d in %d requests", rep.Tested, len(f.requests))
	}
}

func TestSelfTestFlagsABadTestSet(t *testing.T) {
	current := proposal(t, `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["ssm:*","dynamodb:*","s3:*"],"Resource":"*"}]}`)
	rep, err := replayer(&fakeSimulator{}).ReplayWithSelfTest(context.Background(), proposal(t, goodProposal), current, profile())
	if err != nil {
		t.Fatal(err)
	}
	// The current policy has no ec2 at all, so ec2:DescribeRegions in the test
	// set cannot be a real usage of this policy.
	if len(rep.Warnings) != 1 || !strings.Contains(rep.Warnings[0], "CURRENT policy also denies ec2:DescribeRegions") {
		t.Errorf("warnings = %v", rep.Warnings)
	}
}

// Regression for the Day 4 dry runs: once Access Advisor caught up, it listed
// ssm:GetParameter and dynamodb:DescribeTable as tracked actions. Testing them
// on "*" made a correctly scoped proposal look like it would deny them.
func TestTrackedActionsThatWereObservedAreNotTestedOnStar(t *testing.T) {
	p := profile()
	t0 := inside
	p.ServicesAccessed = append(p.ServicesAccessed,
		observe.ServiceAccess{Namespace: "ssm", LastAuthenticated: &t0, TrackedActions: []observe.TrackedAction{{Action: "ssm:GetParameter", LastAccessed: inside}}},
		observe.ServiceAccess{Namespace: "dynamodb", LastAuthenticated: &t0, TrackedActions: []observe.TrackedAction{{Action: "dynamodb:DescribeTable", LastAccessed: inside}}},
	)
	calls, _ := TestSet(p)
	for _, c := range calls {
		if c.Resource == "*" && (c.Action == "ssm:GetParameter" || c.Action == "dynamodb:DescribeTable") {
			t.Errorf("%s tested on * although it was observed on a concrete resource", c.Action)
		}
	}
	rep, err := replayer(&fakeSimulator{}).Replay(context.Background(), proposal(t, goodProposal), p)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Denied) != 0 || rep.Tested != 4 {
		t.Errorf("scoped proposal: tested %d, denied %+v", rep.Tested, rep.Denied)
	}
}
