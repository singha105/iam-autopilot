package generate

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"

	"github.com/singha105/iam-autopilot/internal/policy"
)

// ManagedPath is the only IAM path the autopilot may modify.
const ManagedPath = "/iamap/managed/"

// IAMAPI is the subset of the IAM client CurrentPolicy uses (all read-only).
type IAMAPI interface {
	ListAttachedRolePolicies(context.Context, *iam.ListAttachedRolePoliciesInput, ...func(*iam.Options)) (*iam.ListAttachedRolePoliciesOutput, error)
	GetPolicy(context.Context, *iam.GetPolicyInput, ...func(*iam.Options)) (*iam.GetPolicyOutput, error)
	GetPolicyVersion(context.Context, *iam.GetPolicyVersionInput, ...func(*iam.Options)) (*iam.GetPolicyVersionOutput, error)
}

// ManagedPolicy is the customer-managed policy the autopilot tightens.
type ManagedPolicy struct {
	ARN       string
	Name      string
	VersionID string
	Document  policy.Document
}

// CurrentPolicy returns the one customer-managed policy under /iamap/managed/
// attached to the role, at its default version, URL-decoded. Zero or several
// such policies is an error: the autopilot changes exactly one per role.
func CurrentPolicy(ctx context.Context, client IAMAPI, roleName string) (ManagedPolicy, error) {
	var candidates []string
	var marker *string
	for {
		out, err := client.ListAttachedRolePolicies(ctx, &iam.ListAttachedRolePoliciesInput{RoleName: aws.String(roleName), Marker: marker})
		if err != nil {
			return ManagedPolicy{}, fmt.Errorf("list policies attached to %s: %w", roleName, err)
		}
		for _, p := range out.AttachedPolicies {
			arn := aws.ToString(p.PolicyArn)
			if policyPath(arn) == ManagedPath && !isAWSManaged(arn) {
				candidates = append(candidates, arn)
			}
		}
		if !out.IsTruncated || out.Marker == nil {
			break
		}
		marker = out.Marker
	}
	switch len(candidates) {
	case 0:
		return ManagedPolicy{}, fmt.Errorf("role %s has no customer-managed policy under %s; nothing the autopilot may change", roleName, ManagedPath)
	case 1:
	default:
		return ManagedPolicy{}, fmt.Errorf("role %s has %d policies under %s (%s); the autopilot manages exactly one per role", roleName, len(candidates), ManagedPath, strings.Join(candidates, ", "))
	}

	arn := candidates[0]
	got, err := client.GetPolicy(ctx, &iam.GetPolicyInput{PolicyArn: aws.String(arn)})
	if err != nil {
		return ManagedPolicy{}, fmt.Errorf("get policy %s: %w", arn, err)
	}
	if got.Policy == nil || aws.ToString(got.Policy.Path) != ManagedPath {
		return ManagedPolicy{}, fmt.Errorf("policy %s is not under %s", arn, ManagedPath)
	}
	versionID := aws.ToString(got.Policy.DefaultVersionId)
	ver, err := client.GetPolicyVersion(ctx, &iam.GetPolicyVersionInput{PolicyArn: aws.String(arn), VersionId: aws.String(versionID)})
	if err != nil {
		return ManagedPolicy{}, fmt.Errorf("get policy %s version %s: %w", arn, versionID, err)
	}
	if ver.PolicyVersion == nil {
		return ManagedPolicy{}, fmt.Errorf("get policy %s version %s: empty response", arn, versionID)
	}
	// IAM returns the document URL-encoded (RFC 3986).
	decoded, err := url.QueryUnescape(aws.ToString(ver.PolicyVersion.Document))
	if err != nil {
		return ManagedPolicy{}, fmt.Errorf("decode policy %s: %w", arn, err)
	}
	doc, err := policy.Parse([]byte(decoded))
	if err != nil {
		return ManagedPolicy{}, fmt.Errorf("policy %s: %w", arn, err)
	}
	return ManagedPolicy{ARN: arn, Name: aws.ToString(got.Policy.PolicyName), VersionID: versionID, Document: doc}, nil
}

// policyPath extracts the path from a policy ARN:
// arn:aws:iam::123456789012:policy/iamap/managed/name -> /iamap/managed/
func policyPath(arn string) string {
	_, rest, ok := strings.Cut(arn, ":policy/")
	if !ok {
		return ""
	}
	i := strings.LastIndex(rest, "/")
	if i < 0 {
		return "/"
	}
	return "/" + rest[:i+1]
}

// isAWSManaged reports whether the ARN is an AWS-managed policy (account "aws").
func isAWSManaged(arn string) bool {
	return strings.Contains(arn, ":iam::aws:policy/")
}
