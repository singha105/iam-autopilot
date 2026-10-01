package observe

import (
	"context"
	"encoding/json"
	"strconv"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	cttypes "github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"golang.org/x/time/rate"
)

const (
	testAccount  = "123456789012"
	testRoleARN  = "arn:aws:iam::123456789012:role/iamap-demo-inventory-role"
	testFunction = "iamap-demo-inventory"
)

var testNow = time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)

var testRole = Role{Name: "iamap-demo-inventory-role", ARN: testRoleARN, FunctionName: testFunction}

// testObserver returns an Observer with no rate limit, a fixed clock and a
// sleep that records durations instead of waiting.
func testObserver(ct CloudTrailAPI, iamClient IAMAPI) (*Observer, *[]time.Duration) {
	o := New(ct, iamClient, nil)
	o.Limiter = rate.NewLimiter(rate.Inf, 1)
	o.Now = func() time.Time { return testNow }
	var slept []time.Duration
	o.Sleep = func(_ context.Context, d time.Duration) error {
		slept = append(slept, d)
		return nil
	}
	return o, &slept
}

// ev describes one CloudTrail event for tests.
type ev struct {
	issuer, source, name string
	at                   time.Time
	errorCode, invokedBy string
	userAgent            string
	params               map[string]any
	readOnly             *bool
}

func (e ev) event(t *testing.T) cttypes.Event {
	t.Helper()
	issuer := e.issuer
	if issuer == "" {
		issuer = testRoleARN
	}
	at := e.at
	if at.IsZero() {
		at = testNow.Add(-time.Hour)
	}
	ui := map[string]any{
		"type": "AssumedRole",
		"sessionContext": map[string]any{
			"sessionIssuer": map[string]any{"type": "Role", "arn": issuer},
		},
	}
	if e.invokedBy != "" {
		ui["invokedBy"] = e.invokedBy
	}
	doc := map[string]any{
		"eventSource":        e.source,
		"eventName":          e.name,
		"eventTime":          at.Format(time.RFC3339),
		"awsRegion":          "us-east-1",
		"recipientAccountId": testAccount,
		"userIdentity":       ui,
		"requestParameters":  e.params,
	}
	if e.errorCode != "" {
		doc["errorCode"] = e.errorCode
	}
	if e.userAgent != "" {
		doc["userAgent"] = e.userAgent
	}
	ro := true
	if e.readOnly != nil {
		ro = *e.readOnly
	}
	doc["readOnly"] = ro
	b, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return cttypes.Event{
		EventId:         aws.String(e.name + at.Format(time.RFC3339Nano)),
		EventName:       aws.String(e.name),
		EventSource:     aws.String(e.source),
		EventTime:       aws.Time(at),
		Username:        aws.String(testFunction),
		CloudTrailEvent: aws.String(string(b)),
	}
}

// fakeCloudTrail serves pages in order and can fail the first calls.
type fakeCloudTrail struct {
	pages  [][]cttypes.Event
	errs   []error // returned, one per call, before any page is served
	inputs []cloudtrail.LookupEventsInput
}

func (f *fakeCloudTrail) LookupEvents(_ context.Context, in *cloudtrail.LookupEventsInput, _ ...func(*cloudtrail.Options)) (*cloudtrail.LookupEventsOutput, error) {
	f.inputs = append(f.inputs, *in)
	if len(f.errs) > 0 {
		err := f.errs[0]
		f.errs = f.errs[1:]
		return nil, err
	}
	i := 0
	if in.NextToken != nil {
		n, err := strconv.Atoi(*in.NextToken)
		if err != nil {
			return nil, err
		}
		i = n
	}
	out := &cloudtrail.LookupEventsOutput{}
	if i < len(f.pages) {
		out.Events = f.pages[i]
	}
	if i+1 < len(f.pages) {
		out.NextToken = aws.String(strconv.Itoa(i + 1))
	}
	return out, nil
}

// fakeIAM is a scripted IAM client.
type fakeIAM struct {
	role      *iam.GetRoleOutput
	tagPages  []*iam.ListRoleTagsOutput
	tagCalls  int
	generate  *iam.GenerateServiceLastAccessedDetailsOutput
	details   []*iam.GetServiceLastAccessedDetailsOutput
	detailIn  []iam.GetServiceLastAccessedDetailsInput
	detailIdx int
}

func (f *fakeIAM) GetRole(context.Context, *iam.GetRoleInput, ...func(*iam.Options)) (*iam.GetRoleOutput, error) {
	return f.role, nil
}

func (f *fakeIAM) ListRoleTags(context.Context, *iam.ListRoleTagsInput, ...func(*iam.Options)) (*iam.ListRoleTagsOutput, error) {
	p := f.tagPages[f.tagCalls]
	f.tagCalls++
	return p, nil
}

func (f *fakeIAM) GenerateServiceLastAccessedDetails(context.Context, *iam.GenerateServiceLastAccessedDetailsInput, ...func(*iam.Options)) (*iam.GenerateServiceLastAccessedDetailsOutput, error) {
	return f.generate, nil
}

func (f *fakeIAM) GetServiceLastAccessedDetails(_ context.Context, in *iam.GetServiceLastAccessedDetailsInput, _ ...func(*iam.Options)) (*iam.GetServiceLastAccessedDetailsOutput, error) {
	f.detailIn = append(f.detailIn, *in)
	d := f.details[f.detailIdx]
	if f.detailIdx < len(f.details)-1 {
		f.detailIdx++
	}
	return d, nil
}
