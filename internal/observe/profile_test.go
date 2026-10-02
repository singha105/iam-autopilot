package observe

import (
	"bytes"
	"context"
	"math/rand"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	cttypes "github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
)

func managedRoleIAM() *fakeIAM {
	return &fakeIAM{
		role: &iam.GetRoleOutput{Role: &iamtypes.Role{RoleName: aws.String(testRole.Name), Arn: aws.String(testRoleARN)}},
		tagPages: []*iam.ListRoleTagsOutput{{Tags: []iamtypes.Tag{
			{Key: aws.String(TagManaged), Value: aws.String("true")},
			{Key: aws.String(TagFunction), Value: aws.String(testFunction)},
		}}},
		generate: &iam.GenerateServiceLastAccessedDetailsOutput{JobId: aws.String("job-1")},
	}
}

func completed(services ...iamtypes.ServiceLastAccessed) *iam.GetServiceLastAccessedDetailsOutput {
	return &iam.GetServiceLastAccessedDetailsOutput{JobStatus: iamtypes.JobStatusTypeCompleted, ServicesLastAccessed: services}
}

func svc(ns string, last *time.Time, tracked ...iamtypes.TrackedActionLastAccessed) iamtypes.ServiceLastAccessed {
	return iamtypes.ServiceLastAccessed{ServiceNamespace: aws.String(ns), LastAuthenticated: last, TrackedActionsLastAccessed: tracked}
}

func TestCollectServiceAccessPollsAndPaginates(t *testing.T) {
	used := testNow.Add(-time.Hour)
	f := managedRoleIAM()
	inProgress := &iam.GetServiceLastAccessedDetailsOutput{JobStatus: iamtypes.JobStatusTypeInProgress}
	page1 := completed(svc("sqs", nil), svc("ec2", &used,
		iamtypes.TrackedActionLastAccessed{ActionName: aws.String("DescribeRegions"), LastAccessedTime: &used},
		iamtypes.TrackedActionLastAccessed{ActionName: aws.String("RunInstances")}, // never used: dropped
	))
	page1.IsTruncated, page1.Marker = true, aws.String("page2")
	f.details = []*iam.GetServiceLastAccessedDetailsOutput{inProgress, inProgress, page1, completed(svc("dynamodb", &used))}

	o, slept := testObserver(nil, f)
	got, err := o.CollectServiceAccess(context.Background(), testRole)
	if err != nil {
		t.Fatal(err)
	}
	if want := []time.Duration{2 * time.Second, 2 * time.Second}; !reflect.DeepEqual(*slept, want) {
		t.Errorf("polls slept %v, want %v", *slept, want)
	}
	if aws.ToString(f.detailIn[3].Marker) != "page2" || aws.ToString(f.detailIn[0].JobId) != "job-1" {
		t.Errorf("marker/job not passed: %+v", f.detailIn)
	}
	want := []ServiceAccess{
		{Namespace: "dynamodb", LastAuthenticated: &used, TrackedActions: []TrackedAction{}},
		{Namespace: "ec2", LastAuthenticated: &used, TrackedActions: []TrackedAction{{Action: "ec2:DescribeRegions", LastAccessed: used}}},
		{Namespace: "sqs", TrackedActions: []TrackedAction{}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("services =\n%+v\nwant\n%+v", got, want)
	}
}

func TestCollectServiceAccessFailedJob(t *testing.T) {
	f := managedRoleIAM()
	f.details = []*iam.GetServiceLastAccessedDetailsOutput{{
		JobStatus: iamtypes.JobStatusTypeFailed,
		Error:     &iamtypes.ErrorDetails{Code: aws.String("InternalError"), Message: aws.String("try again")},
	}}
	o, _ := testObserver(nil, f)
	_, err := o.CollectServiceAccess(context.Background(), testRole)
	if err == nil || !strings.Contains(err.Error(), "try again") {
		t.Fatalf("err = %v, want job failure", err)
	}
}

func TestCollectServiceAccessTimesOut(t *testing.T) {
	f := managedRoleIAM()
	f.details = []*iam.GetServiceLastAccessedDetailsOutput{{JobStatus: iamtypes.JobStatusTypeInProgress}}
	o, slept := testObserver(nil, f)
	_, err := o.CollectServiceAccess(context.Background(), testRole)
	if err == nil || !strings.Contains(err.Error(), "still IN_PROGRESS") {
		t.Fatalf("err = %v, want timeout", err)
	}
	if len(*slept) != 30 {
		t.Errorf("slept %d times, want 30 (60s / 2s)", len(*slept))
	}
}

func TestAssembleFiltersServicesToWindow(t *testing.T) {
	w := Window{Start: testNow.Add(-day(1)), End: testNow}
	inside, before := testNow.Add(-time.Hour), testNow.Add(-day(3))
	services := []ServiceAccess{
		{Namespace: "ssm", LastAuthenticated: &inside, TrackedActions: []TrackedAction{}},
		{Namespace: "ec2", LastAuthenticated: &before, TrackedActions: []TrackedAction{{Action: "ec2:DescribeRegions", LastAccessed: before}}},
		{Namespace: "sns", TrackedActions: []TrackedAction{}},
	}
	p := assemble(testRole, EventsResult{Window: w}, services)
	if got := p.AccessedServices(); !reflect.DeepEqual(got, []string{"ssm"}) {
		t.Errorf("accessed = %v, want [ssm]", got)
	}
	for _, s := range p.ServicesAccessed {
		if s.Namespace == "ec2" && (s.LastAuthenticated != nil || len(s.TrackedActions) != 0) {
			t.Errorf("ec2 used before the window still reported: %+v", s)
		}
	}
}

func TestAssembleWarnsAboutAccessAdvisorLag(t *testing.T) {
	w := Window{Start: testNow.Add(-day(1)), End: testNow}
	ev := EventsResult{Window: w, Calls: []ObservedCall{{Action: "iam:ListRoles", Resource: "*", Count: 1}}}
	p := assemble(testRole, ev, []ServiceAccess{{Namespace: "iam", TrackedActions: []TrackedAction{}}})
	if !containsSubstring(p.Warnings, "lag by up to about 4 hours") {
		t.Errorf("warnings = %v, want the Access Advisor lag warning", p.Warnings)
	}
}

func TestEmptyProfileEncodesEmptyLists(t *testing.T) {
	p := assemble(testRole, EventsResult{Window: Window{Start: testNow.Add(-day(1)), End: testNow}}, nil)
	b, err := p.Encode()
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{`"observedCalls": []`, `"servicesAccessed": []`, `"deniedCalls": []`, `"excludedCalls": []`, `"warnings": []`} {
		if !bytes.Contains(b, []byte(field)) {
			t.Errorf("encoded profile lacks %s:\n%s", field, b)
		}
	}
}

// TestBuildProfileIsDeterministic builds the same profile twice, the second
// time from shuffled events and services, and requires identical bytes.
func TestBuildProfileIsDeterministic(t *testing.T) {
	used := testNow.Add(-2 * time.Hour)
	events := func() []cttypes.Event {
		return []cttypes.Event{
			ev{source: "ssm.amazonaws.com", name: "GetParameter", at: testNow.Add(-5 * time.Hour), params: map[string]any{"name": "/b"}}.event(t),
			ev{source: "ssm.amazonaws.com", name: "GetParameter", at: testNow.Add(-4 * time.Hour), params: map[string]any{"name": "/a"}}.event(t),
			ev{source: "ec2.amazonaws.com", name: "DescribeRegions", at: testNow.Add(-3 * time.Hour)}.event(t),
			ev{source: "sns.amazonaws.com", name: "Publish", at: testNow.Add(-3 * time.Hour), errorCode: "AuthorizationError"}.event(t),
			ev{source: "ec2.amazonaws.com", name: "DescribeInstances", at: testNow.Add(-3 * time.Hour), errorCode: "Client.UnauthorizedOperation"}.event(t),
			ev{source: "kms.amazonaws.com", name: "Decrypt", invokedBy: "lambda.amazonaws.com"}.event(t),
			ev{issuer: "arn:aws:iam::123456789012:role/other", source: "iam.amazonaws.com", name: "ListRoles"}.event(t),
		}
	}
	services := func() []iamtypes.ServiceLastAccessed {
		return []iamtypes.ServiceLastAccessed{svc("ssm", &used), svc("ec2", &used,
			iamtypes.TrackedActionLastAccessed{ActionName: aws.String("DescribeRegions"), LastAccessedTime: &used},
			iamtypes.TrackedActionLastAccessed{ActionName: aws.String("DescribeInstances"), LastAccessedTime: &used},
		), svc("sns", nil)}
	}

	build := func(shuffle bool) []byte {
		evs, ss := events(), services()
		if shuffle {
			r := rand.New(rand.NewSource(7))
			r.Shuffle(len(evs), func(i, j int) { evs[i], evs[j] = evs[j], evs[i] })
			r.Shuffle(len(ss), func(i, j int) { ss[i], ss[j] = ss[j], ss[i] })
			for k := range ss {
				r.Shuffle(len(ss[k].TrackedActionsLastAccessed), func(i, j int) {
					ss[k].TrackedActionsLastAccessed[i], ss[k].TrackedActionsLastAccessed[j] = ss[k].TrackedActionsLastAccessed[j], ss[k].TrackedActionsLastAccessed[i]
				})
			}
		}
		f := managedRoleIAM()
		f.details = []*iam.GetServiceLastAccessedDetailsOutput{completed(ss...)}
		o, _ := testObserver(&fakeCloudTrail{pages: [][]cttypes.Event{evs[:3], evs[3:]}}, f)
		p, err := o.BuildProfile(context.Background(), testRole.Name, testNow.Add(-day(1)), testNow)
		if err != nil {
			t.Fatal(err)
		}
		b, err := p.Encode()
		if err != nil {
			t.Fatal(err)
		}
		return b
	}

	first, again, shuffled := build(false), build(false), build(true)
	if !bytes.Equal(first, again) {
		t.Errorf("same input, different bytes:\n%s\n---\n%s", first, again)
	}
	if !bytes.Equal(first, shuffled) {
		t.Errorf("shuffled input, different bytes:\n%s\n---\n%s", first, shuffled)
	}
}
