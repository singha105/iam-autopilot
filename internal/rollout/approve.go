package rollout

import (
	"context"
	"errors"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sfn"

	"github.com/singha105/iam-autopilot/internal/githubpr"
	"github.com/singha105/iam-autopilot/internal/store"
)

// ErrorPRClosed is the Step Functions error name for a PR closed unmerged;
// the state machine catches it and cancels the rollout.
const ErrorPRClosed = "PRClosed"

// ErrNotDecided means the PR is neither merged nor closed: nothing happens.
var ErrNotDecided = errors.New("PR is still open; nothing to approve")

// StatesAPI resumes the state machine waiting on the approval task token.
type StatesAPI interface {
	SendTaskSuccess(context.Context, *sfn.SendTaskSuccessInput, ...func(*sfn.Options)) (*sfn.SendTaskSuccessOutput, error)
	SendTaskFailure(context.Context, *sfn.SendTaskFailureInput, ...func(*sfn.Options)) (*sfn.SendTaskFailureOutput, error)
}

// MergeChecker reads a PR's merge state.
type MergeChecker interface {
	IsMerged(context.Context, int) (githubpr.MergeInfo, error)
}

// Approver handles the one step the approver Lambda accepts.
type Approver struct {
	Store  Records
	GitHub MergeChecker
	States StatesAPI
}

// ApproveResult says what the approver did.
type ApproveResult struct {
	Decision string `json:"decision"` // approved | cancelled | already-approved
	MergedBy string `json:"mergedBy,omitempty"`
}

// Approve is called by the GitHub workflow when an autopilot/ PR closes. It
// never trusts the caller: it checks the PR number against the record and
// asks GitHub whether the PR was really merged. Merged -> APPROVED and
// SendTaskSuccess; closed unmerged -> SendTaskFailure(PRClosed); anything
// else -> error, nothing changes.
func (a *Approver) Approve(ctx context.Context, id string, prNumber int, approvedAt string) (ApproveResult, error) {
	r, err := a.Store.Get(ctx, id)
	if err != nil {
		return ApproveResult{}, err
	}
	if r.PRNumber == 0 || r.PRNumber != prNumber {
		return ApproveResult{}, fmt.Errorf("rollout %s belongs to PR #%d, not #%d", id, r.PRNumber, prNumber)
	}
	info, err := a.GitHub.IsMerged(ctx, prNumber)
	if err != nil {
		return ApproveResult{}, err
	}
	switch {
	case info.Merged && r.Status == store.StatusApproved:
		return ApproveResult{Decision: "already-approved", MergedBy: info.MergedBy}, nil
	case info.Merged:
		if r.TaskToken == "" {
			return ApproveResult{}, fmt.Errorf("rollout %s has no task token yet; re-run the workflow in a minute", id)
		}
		if err := a.Store.UpdateStatus(ctx, id, store.StatusPROpen, store.StatusApproved); err != nil {
			return ApproveResult{}, err
		}
		if err := a.Store.SetFields(ctx, id, map[string]any{"approvedAt": approvedAt}); err != nil {
			return ApproveResult{}, err
		}
		_, err := a.States.SendTaskSuccess(ctx, &sfn.SendTaskSuccessInput{TaskToken: aws.String(r.TaskToken), Output: aws.String(`{"approved":true}`)})
		if err != nil {
			return ApproveResult{}, fmt.Errorf("resume rollout %s: %w", id, err)
		}
		return ApproveResult{Decision: "approved", MergedBy: info.MergedBy}, nil
	case info.State == "closed":
		if r.TaskToken == "" {
			return ApproveResult{}, fmt.Errorf("rollout %s has no task token to fail", id)
		}
		_, err := a.States.SendTaskFailure(ctx, &sfn.SendTaskFailureInput{
			TaskToken: aws.String(r.TaskToken), Error: aws.String(ErrorPRClosed), Cause: aws.String(fmt.Sprintf("PR #%d was closed without merging", prNumber)),
		})
		if err != nil {
			return ApproveResult{}, fmt.Errorf("cancel rollout %s: %w", id, err)
		}
		return ApproveResult{Decision: "cancelled"}, nil
	default:
		return ApproveResult{}, fmt.Errorf("%w (PR #%d is %s)", ErrNotDecided, prNumber, info.State)
	}
}
