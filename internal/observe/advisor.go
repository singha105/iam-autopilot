package observe

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
)

// CollectServiceAccess asks IAM Access Advisor which services the role has
// authenticated to, with action-level detail where the API provides it.
//
// Access Advisor sees data-plane calls (DynamoDB GetItem, S3 GetObject) that
// CloudTrail event history never records, but only at service granularity for
// most services, and its data can lag by up to about 4 hours: a service used
// in the last few hours may still show as never used.
//
// Every service the role's policies grant is returned, with LastAuthenticated
// as reported (nil = never used). Which services have action-level tracking is
// whatever the API returns; nothing is hardcoded. Tracked actions that were
// never used are dropped.
func (o *Observer) CollectServiceAccess(ctx context.Context, role Role) ([]ServiceAccess, error) {
	gen, err := o.IAM.GenerateServiceLastAccessedDetails(ctx, &iam.GenerateServiceLastAccessedDetailsInput{
		Arn:         aws.String(role.ARN),
		Granularity: iamtypes.AccessAdvisorUsageGranularityTypeActionLevel,
	})
	if err != nil {
		return nil, fmt.Errorf("generate service last accessed details for %s: %w", role.Name, err)
	}
	jobID := aws.ToString(gen.JobId)

	var (
		services []ServiceAccess
		marker   *string
		waited   time.Duration
		polls    int
	)
	for {
		out, err := o.IAM.GetServiceLastAccessedDetails(ctx, &iam.GetServiceLastAccessedDetailsInput{JobId: aws.String(jobID), Marker: marker})
		if err != nil {
			return nil, fmt.Errorf("get service last accessed details (job %s): %w", jobID, err)
		}
		polls++

		switch out.JobStatus {
		case iamtypes.JobStatusTypeCompleted:
			for _, s := range out.ServicesLastAccessed {
				services = append(services, toServiceAccess(s))
			}
			if out.IsTruncated && out.Marker != nil {
				marker = out.Marker
				continue
			}
			sortServices(services)
			o.Log.Info("access advisor read", "role", role.Name, "job", jobID, "polls", polls, "services", len(services))
			return services, nil

		case iamtypes.JobStatusTypeFailed:
			msg := "no detail"
			if out.Error != nil {
				msg = aws.ToString(out.Error.Code) + ": " + aws.ToString(out.Error.Message)
			}
			return nil, fmt.Errorf("access advisor job %s failed: %s", jobID, msg)

		default: // IN_PROGRESS
			if waited >= o.AdvisorTimeout {
				return nil, fmt.Errorf("access advisor job %s still %s after %s", jobID, out.JobStatus, o.AdvisorTimeout)
			}
			if err := o.Sleep(ctx, o.AdvisorPollInterval); err != nil {
				return nil, err
			}
			waited += o.AdvisorPollInterval
		}
	}
}

func toServiceAccess(s iamtypes.ServiceLastAccessed) ServiceAccess {
	ns := aws.ToString(s.ServiceNamespace)
	sa := ServiceAccess{Namespace: ns, TrackedActions: []TrackedAction{}}
	if s.LastAuthenticated != nil {
		t := s.LastAuthenticated.UTC()
		sa.LastAuthenticated = &t
	}
	for _, a := range s.TrackedActionsLastAccessed {
		if a.LastAccessedTime == nil {
			continue
		}
		name := aws.ToString(a.ActionName)
		if !strings.Contains(name, ":") {
			name = ns + ":" + name
		}
		sa.TrackedActions = append(sa.TrackedActions, TrackedAction{Action: name, LastAccessed: a.LastAccessedTime.UTC()})
	}
	return sa
}

func sortServices(ss []ServiceAccess) {
	sort.Slice(ss, func(i, j int) bool { return ss[i].Namespace < ss[j].Namespace })
	for _, s := range ss {
		sort.Slice(s.TrackedActions, func(i, j int) bool { return s.TrackedActions[i].Action < s.TrackedActions[j].Action })
	}
}
