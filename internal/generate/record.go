package generate

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/service/iam"

	"github.com/singha105/iam-autopilot/internal/observe"
)

// Fixture operation names for CurrentPolicy's calls.
const (
	OpListAttachedRolePolicies = "list-attached-role-policies"
	OpGetPolicy                = "get-policy"
	OpGetPolicyVersion         = "get-policy-version"
)

// RecordingIAM saves every successful CurrentPolicy response as a redacted
// fixture, like observe.RecordingIAM does for the observer.
type RecordingIAM struct {
	Inner IAMAPI
	Rec   *observe.Recorder
}

func (c RecordingIAM) ListAttachedRolePolicies(ctx context.Context, in *iam.ListAttachedRolePoliciesInput, opts ...func(*iam.Options)) (*iam.ListAttachedRolePoliciesOutput, error) {
	out, err := c.Inner.ListAttachedRolePolicies(ctx, in, opts...)
	return out, save(c.Rec, OpListAttachedRolePolicies, out, err)
}

func (c RecordingIAM) GetPolicy(ctx context.Context, in *iam.GetPolicyInput, opts ...func(*iam.Options)) (*iam.GetPolicyOutput, error) {
	out, err := c.Inner.GetPolicy(ctx, in, opts...)
	return out, save(c.Rec, OpGetPolicy, out, err)
}

func (c RecordingIAM) GetPolicyVersion(ctx context.Context, in *iam.GetPolicyVersionInput, opts ...func(*iam.Options)) (*iam.GetPolicyVersionOutput, error) {
	out, err := c.Inner.GetPolicyVersion(ctx, in, opts...)
	return out, save(c.Rec, OpGetPolicyVersion, out, err)
}

func save(rec *observe.Recorder, op string, out any, err error) error {
	if err != nil {
		return err
	}
	return rec.Save(op, out)
}
