package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	cttypes "github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"

	"github.com/singha105/iam-autopilot/internal/observe"
)

func TestRunUsage(t *testing.T) {
	tests := []struct {
		args     []string
		wantCode int
		wantErr  string
	}{
		{nil, 2, "Usage:"},
		{[]string{"bogus"}, 2, `unknown command "bogus"`},
		{[]string{"observe"}, 2, "--role is required"},
		{[]string{"observe", "--role", "r", "--days", "0"}, 2, "--days must be at least 1"},
		{[]string{"observe", "--role", "r", "extra"}, 2, "unexpected arguments: extra"},
		{[]string{"observe", "-h"}, 0, "Usage: autopilot observe"},
	}
	for _, tt := range tests {
		var stdout, stderr bytes.Buffer
		code := run(context.Background(), tt.args, &stdout, &stderr)
		if code != tt.wantCode {
			t.Errorf("run(%v) = %d, want %d", tt.args, code, tt.wantCode)
		}
		if !strings.Contains(stderr.String()+stdout.String(), tt.wantErr) {
			t.Errorf("run(%v) output lacks %q:\n%s", tt.args, tt.wantErr, stderr.String())
		}
	}
}

func TestParseObserveFlagsDefaults(t *testing.T) {
	o, err := parseObserveFlags([]string{"--role", "iamap-demo-quarterly-role"}, &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	want := observeOptions{role: "iamap-demo-quarterly-role", days: 90, region: "us-east-1", out: filepath.Join("build", "profiles", "iamap-demo-quarterly-role.json")}
	if o != want {
		t.Errorf("options = %+v, want %+v", o, want)
	}
}

type stubCloudTrail struct{ events []cttypes.Event }

func (s stubCloudTrail) LookupEvents(context.Context, *cloudtrail.LookupEventsInput, ...func(*cloudtrail.Options)) (*cloudtrail.LookupEventsOutput, error) {
	return &cloudtrail.LookupEventsOutput{Events: s.events}, nil
}

type stubIAM struct{ tags []iamtypes.Tag }

func (s stubIAM) GetRole(context.Context, *iam.GetRoleInput, ...func(*iam.Options)) (*iam.GetRoleOutput, error) {
	return &iam.GetRoleOutput{Role: &iamtypes.Role{RoleName: aws.String("demo-role"), Arn: aws.String("arn:aws:iam::987654321098:role/demo-role")}}, nil
}

func (s stubIAM) ListRoleTags(context.Context, *iam.ListRoleTagsInput, ...func(*iam.Options)) (*iam.ListRoleTagsOutput, error) {
	return &iam.ListRoleTagsOutput{Tags: s.tags}, nil
}

func (s stubIAM) GenerateServiceLastAccessedDetails(context.Context, *iam.GenerateServiceLastAccessedDetailsInput, ...func(*iam.Options)) (*iam.GenerateServiceLastAccessedDetailsOutput, error) {
	return &iam.GenerateServiceLastAccessedDetailsOutput{JobId: aws.String("j")}, nil
}

func (s stubIAM) GetServiceLastAccessedDetails(context.Context, *iam.GetServiceLastAccessedDetailsInput, ...func(*iam.Options)) (*iam.GetServiceLastAccessedDetailsOutput, error) {
	used := time.Date(2026, 9, 30, 11, 0, 0, 0, time.UTC)
	return &iam.GetServiceLastAccessedDetailsOutput{JobStatus: iamtypes.JobStatusTypeCompleted, ServicesLastAccessed: []iamtypes.ServiceLastAccessed{
		{ServiceNamespace: aws.String("ssm"), LastAuthenticated: &used},
		{ServiceNamespace: aws.String("sns")},
	}}, nil
}

func TestObserveEndToEndWithRecording(t *testing.T) {
	dir := t.TempDir()
	at := time.Date(2026, 9, 30, 10, 0, 0, 0, time.UTC)
	ctEvent := `{"eventSource":"ssm.amazonaws.com","eventName":"GetParameter","eventTime":"2026-09-30T10:00:00Z","awsRegion":"us-east-1","recipientAccountId":"987654321098","readOnly":true,"requestParameters":{"name":"/iamap/demo/config"},"userIdentity":{"accessKeyId":"ASIAQQQQQQQQQQQQQQQQ","sessionContext":{"sessionIssuer":{"arn":"arn:aws:iam::987654321098:role/demo-role"}}}}`
	tags := []iamtypes.Tag{{Key: aws.String("autopilot:managed"), Value: aws.String("true")}, {Key: aws.String("autopilot:function"), Value: aws.String("demo-fn")}}

	oldLoad, oldNow := loadClients, now
	t.Cleanup(func() { loadClients, now = oldLoad, oldNow })
	now = func() time.Time { return time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC) }
	loadClients = func(context.Context, string) (awsClients, error) {
		return awsClients{
			CloudTrail: stubCloudTrail{events: []cttypes.Event{{EventTime: &at, CloudTrailEvent: aws.String(ctEvent)}}},
			IAM:        stubIAM{tags: tags},
			AccountID:  func(context.Context) (string, error) { return "987654321098", nil },
		}, nil
	}

	out := filepath.Join(dir, "profile.json")
	rec := filepath.Join(dir, "fixtures")
	var stdout, stderr bytes.Buffer
	if code := run(context.Background(), []string{"observe", "--role", "demo-role", "--days", "1", "--out", out, "--record", rec}, &stdout, &stderr); code != 0 {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}

	for _, want := range []string{"Observed actions (1)", "ssm:GetParameter", "Services accessed (1 of 2 granted)", "not used in window: sns", "Denied calls (0)", "Profile written to " + out} {
		if !strings.Contains(stdout.String(), want) {
			t.Errorf("summary lacks %q:\n%s", want, stdout.String())
		}
	}
	if !strings.Contains(stderr.String(), "pages=1") {
		t.Errorf("page count not logged: %s", stderr.String())
	}

	var p observe.Profile
	b, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &p); err != nil {
		t.Fatal(err)
	}
	if p.RoleName != "demo-role" || len(p.ObservedCalls) != 1 || p.Window.End != now() {
		t.Errorf("profile = %+v", p)
	}

	files, _ := filepath.Glob(filepath.Join(rec, "*.json"))
	if len(files) != 6 { // meta + get-role + list-role-tags + generate + get-details + lookup-events
		t.Errorf("recorded %d files, want 6: %v", len(files), files)
	}
	for _, f := range files {
		raw, _ := os.ReadFile(f)
		if bytes.Contains(raw, []byte("987654321098")) || bytes.Contains(raw, []byte("ASIAQQQQ")) {
			t.Errorf("%s is not redacted", filepath.Base(f))
		}
	}
}
