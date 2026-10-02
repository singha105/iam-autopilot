package generate

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/accessanalyzer"
	aatypes "github.com/aws/aws-sdk-go-v2/service/accessanalyzer/types"

	"github.com/singha105/iam-autopilot/internal/policy"
)

// AccessAnalyzerAPI is the one Access Analyzer call the autopilot makes.
// ValidatePolicy is free. Analyzers and custom policy checks
// (CheckNoNewAccess and friends) are paid and must never be called (ADR-004).
type AccessAnalyzerAPI interface {
	ValidatePolicy(context.Context, *accessanalyzer.ValidatePolicyInput, ...func(*accessanalyzer.Options)) (*accessanalyzer.ValidatePolicyOutput, error)
}

// ErrValidation is returned when a proposal has ERROR or SECURITY_WARNING findings.
var ErrValidation = errors.New("proposed policy failed validation")

// Validate runs Access Analyzer ValidatePolicy on an identity policy and
// returns every finding.
func Validate(ctx context.Context, client AccessAnalyzerAPI, doc policy.Document) ([]Finding, error) {
	js, err := doc.Compact()
	if err != nil {
		return nil, err
	}
	var out []Finding
	in := &accessanalyzer.ValidatePolicyInput{
		PolicyDocument: aws.String(js),
		PolicyType:     aatypes.PolicyTypeIdentityPolicy,
	}
	for {
		page, err := client.ValidatePolicy(ctx, in)
		if err != nil {
			return nil, fmt.Errorf("access analyzer ValidatePolicy: %w", err)
		}
		for _, f := range page.Findings {
			out = append(out, Finding{Type: string(f.FindingType), IssueCode: aws.ToString(f.IssueCode), Message: aws.ToString(f.FindingDetails)})
		}
		if page.NextToken == nil {
			break
		}
		in.NextToken = page.NextToken
	}
	return out, nil
}

// CheckFindings fails on any ERROR or SECURITY_WARNING. WARNING and
// SUGGESTION findings are only reported in the summary.
func CheckFindings(findings []Finding) error {
	var blocking []string
	for _, f := range findings {
		if f.Type == string(aatypes.ValidatePolicyFindingTypeError) || f.Type == string(aatypes.ValidatePolicyFindingTypeSecurityWarning) {
			blocking = append(blocking, f.Type+" "+f.IssueCode+": "+f.Message)
		}
	}
	if len(blocking) > 0 {
		return fmt.Errorf("%w: %s", ErrValidation, strings.Join(blocking, "; "))
	}
	return nil
}
