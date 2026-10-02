package generate

import (
	"context"
	"net/url"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
)

const (
	managedARN = "arn:aws:iam::123456789012:policy/iamap/managed/iamap-demo-quarterly-policy"
	basicExec  = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
)

type fakePolicyIAM struct {
	attached [][]string // pages of attached policy ARNs
	path     string
	doc      string
	page     int
}

func (f *fakePolicyIAM) ListAttachedRolePolicies(context.Context, *iam.ListAttachedRolePoliciesInput, ...func(*iam.Options)) (*iam.ListAttachedRolePoliciesOutput, error) {
	out := &iam.ListAttachedRolePoliciesOutput{}
	for _, arn := range f.attached[f.page] {
		out.AttachedPolicies = append(out.AttachedPolicies, iamtypes.AttachedPolicy{PolicyArn: aws.String(arn)})
	}
	f.page++
	if f.page < len(f.attached) {
		out.IsTruncated, out.Marker = true, aws.String("next")
	}
	return out, nil
}

func (f *fakePolicyIAM) GetPolicy(_ context.Context, in *iam.GetPolicyInput, _ ...func(*iam.Options)) (*iam.GetPolicyOutput, error) {
	return &iam.GetPolicyOutput{Policy: &iamtypes.Policy{Arn: in.PolicyArn, PolicyName: aws.String("iamap-demo-quarterly-policy"), Path: aws.String(f.path), DefaultVersionId: aws.String("v3")}}, nil
}

func (f *fakePolicyIAM) GetPolicyVersion(_ context.Context, in *iam.GetPolicyVersionInput, _ ...func(*iam.Options)) (*iam.GetPolicyVersionOutput, error) {
	return &iam.GetPolicyVersionOutput{PolicyVersion: &iamtypes.PolicyVersion{VersionId: in.VersionId, Document: aws.String(url.QueryEscape(f.doc))}}, nil
}

func TestCurrentPolicy(t *testing.T) {
	doc := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["ssm:*"],"Resource":"*"}]}`
	f := &fakePolicyIAM{attached: [][]string{{basicExec}, {managedARN}}, path: ManagedPath, doc: doc}
	got, err := CurrentPolicy(context.Background(), f, "iamap-demo-quarterly-role")
	if err != nil {
		t.Fatal(err)
	}
	if got.ARN != managedARN || got.VersionID != "v3" || got.Name != "iamap-demo-quarterly-policy" {
		t.Errorf("policy = %+v", got)
	}
	if len(got.Document.Statement) != 1 || got.Document.Statement[0].Action[0] != "ssm:*" {
		t.Errorf("document not URL-decoded and parsed: %+v", got.Document)
	}
}

func TestCurrentPolicyRefuses(t *testing.T) {
	other := "arn:aws:iam::123456789012:policy/iamap/managed/second"
	elsewhere := "arn:aws:iam::123456789012:policy/someone-elses-policy"
	tests := map[string]struct {
		attached []string
		path     string
		want     string
	}{
		"no managed policy":           {[]string{basicExec, elsewhere}, ManagedPath, "no customer-managed policy"},
		"two managed policies":        {[]string{managedARN, other}, ManagedPath, "has 2 policies"},
		"GetPolicy disagrees on path": {[]string{managedARN}, "/other/", "not under /iamap/managed/"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			f := &fakePolicyIAM{attached: [][]string{tt.attached}, path: tt.path, doc: `{"Statement":[]}`}
			_, err := CurrentPolicy(context.Background(), f, "r")
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("err = %v, want %q", err, tt.want)
			}
		})
	}
}

func TestPolicyPath(t *testing.T) {
	for arn, want := range map[string]string{
		managedARN: "/iamap/managed/",
		basicExec:  "/service-role/",
		"arn:aws:iam::123456789012:policy/top-level":  "/",
		"arn:aws:iam::123456789012:role/not-a-policy": "",
	} {
		if got := policyPath(arn); got != want {
			t.Errorf("policyPath(%s) = %q, want %q", arn, got, want)
		}
	}
}
