package generate

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/accessanalyzer"
	aatypes "github.com/aws/aws-sdk-go-v2/service/accessanalyzer/types"
)

type fakeAnalyzer struct {
	pages [][]aatypes.ValidatePolicyFinding
	in    []accessanalyzer.ValidatePolicyInput
}

func (f *fakeAnalyzer) ValidatePolicy(_ context.Context, in *accessanalyzer.ValidatePolicyInput, _ ...func(*accessanalyzer.Options)) (*accessanalyzer.ValidatePolicyOutput, error) {
	f.in = append(f.in, *in)
	i := len(f.in) - 1
	out := &accessanalyzer.ValidatePolicyOutput{Findings: f.pages[i]}
	if i+1 < len(f.pages) {
		out.NextToken = aws.String("next")
	}
	return out, nil
}

func finding(typ aatypes.ValidatePolicyFindingType, code string) aatypes.ValidatePolicyFinding {
	return aatypes.ValidatePolicyFinding{FindingType: typ, IssueCode: aws.String(code), FindingDetails: aws.String(code + " details")}
}

func TestValidate(t *testing.T) {
	f := &fakeAnalyzer{pages: [][]aatypes.ValidatePolicyFinding{
		{finding(aatypes.ValidatePolicyFindingTypeSuggestion, "EMPTY_ARRAY_RESOURCE")},
		{finding(aatypes.ValidatePolicyFindingTypeWarning, "MISSING_VERSION")},
	}}
	got, err := Validate(context.Background(), f, doc(t, allow("ssm:GetParameter")))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || len(f.in) != 2 {
		t.Fatalf("findings = %+v after %d calls", got, len(f.in))
	}
	if f.in[0].PolicyType != aatypes.PolicyTypeIdentityPolicy || !strings.Contains(aws.ToString(f.in[0].PolicyDocument), "ssm:GetParameter") {
		t.Errorf("input = %+v", f.in[0])
	}
	if err := CheckFindings(got); err != nil {
		t.Errorf("WARNING/SUGGESTION must not fail the run: %v", err)
	}
}

func TestValidateSecurityWarningFailsTheRun(t *testing.T) {
	f := &fakeAnalyzer{pages: [][]aatypes.ValidatePolicyFinding{{
		finding(aatypes.ValidatePolicyFindingTypeSecurityWarning, "PASS_ROLE_WITH_STAR_IN_RESOURCE"),
	}}}
	got, err := Validate(context.Background(), f, doc(t, allow("iam:PassRole")))
	if err != nil {
		t.Fatal(err)
	}
	if err := CheckFindings(got); !errors.Is(err, ErrValidation) || !strings.Contains(err.Error(), "PASS_ROLE_WITH_STAR_IN_RESOURCE") {
		t.Errorf("err = %v, want ErrValidation naming the finding", err)
	}
	if err := CheckFindings([]Finding{{Type: "ERROR", IssueCode: "JSON_PARSE_ERROR"}}); !errors.Is(err, ErrValidation) {
		t.Errorf("ERROR must fail: %v", err)
	}
}
