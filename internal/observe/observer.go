package observe

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"golang.org/x/time/rate"
)

// ErrNotManaged is returned for roles without the autopilot:managed=true tag.
var ErrNotManaged = errors.New("role is not managed by the autopilot")

// lookupEventsRate stays under CloudTrail's limit of 2 LookupEvents requests
// per second per account per region.
const lookupEventsRate = 1.5

// Observer builds usage profiles. Use New for production defaults; tests set
// the fields directly to inject fakes, a fixed clock and a no-op sleep.
type Observer struct {
	CloudTrail CloudTrailAPI
	IAM        IAMAPI

	// Limiter paces LookupEvents calls, retries included.
	Limiter *rate.Limiter
	// Now is the clock used for the 90-day clamp and the default window end.
	Now func() time.Time
	// Sleep waits between throttling retries and Access Advisor polls.
	Sleep func(context.Context, time.Duration) error
	Log   *slog.Logger

	// AdvisorPollInterval and AdvisorTimeout bound the Access Advisor job wait.
	AdvisorPollInterval time.Duration
	AdvisorTimeout      time.Duration
}

// New returns an Observer with production defaults. A nil logger discards logs.
func New(ct CloudTrailAPI, iamClient IAMAPI, log *slog.Logger) *Observer {
	if log == nil {
		log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return &Observer{
		CloudTrail:          ct,
		IAM:                 iamClient,
		Limiter:             rate.NewLimiter(rate.Limit(lookupEventsRate), 1),
		Now:                 time.Now,
		Sleep:               sleepCtx,
		Log:                 log,
		AdvisorPollInterval: 2 * time.Second,
		AdvisorTimeout:      60 * time.Second,
	}
}

// ResolveRole loads a role and its tags, and refuses any role that is not
// tagged autopilot:managed=true. The autopilot:function tag names the Lambda
// function: for a role assumed by Lambda, that is the session name CloudTrail
// event history reports as the Username.
func (o *Observer) ResolveRole(ctx context.Context, roleName string) (Role, error) {
	out, err := o.IAM.GetRole(ctx, &iam.GetRoleInput{RoleName: aws.String(roleName)})
	if err != nil {
		return Role{}, fmt.Errorf("get role %s: %w", roleName, err)
	}
	if out.Role == nil {
		return Role{}, fmt.Errorf("get role %s: empty response", roleName)
	}

	tags := map[string]string{}
	var marker *string
	for {
		page, err := o.IAM.ListRoleTags(ctx, &iam.ListRoleTagsInput{RoleName: aws.String(roleName), Marker: marker})
		if err != nil {
			return Role{}, fmt.Errorf("list tags of role %s: %w", roleName, err)
		}
		for _, t := range page.Tags {
			tags[aws.ToString(t.Key)] = aws.ToString(t.Value)
		}
		if !page.IsTruncated || page.Marker == nil {
			break
		}
		marker = page.Marker
	}

	if tags[TagManaged] != "true" {
		return Role{}, fmt.Errorf("role %s is not tagged %s=true; the autopilot refuses to touch it: %w", roleName, TagManaged, ErrNotManaged)
	}
	fn := tags[TagFunction]
	if fn == "" {
		return Role{}, fmt.Errorf("role %s has no %s tag, so its CloudTrail username is unknown", roleName, TagFunction)
	}
	return Role{
		Name:         aws.ToString(out.Role.RoleName),
		ARN:          aws.ToString(out.Role.Arn),
		FunctionName: fn,
		Tags:         tags,
	}, nil
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
