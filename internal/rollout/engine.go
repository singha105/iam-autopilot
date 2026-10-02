package rollout

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	cwtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"

	"github.com/singha105/iam-autopilot/internal/config"
	"github.com/singha105/iam-autopilot/internal/generate"
	"github.com/singha105/iam-autopilot/internal/githubpr"
	"github.com/singha105/iam-autopilot/internal/observe"
	"github.com/singha105/iam-autopilot/internal/store"
)

// maxPolicyVersions is IAM's limit of stored versions per managed policy.
const maxPolicyVersions = 5

// ErrUnsafe means the safety rule failed: the policy is not under
// /iamap/managed/ or the role is not tagged autopilot:managed=true.
var ErrUnsafe = errors.New("refusing to change a policy outside the autopilot's scope")

// PolicyAPI is the IAM subset the enforce/rollback steps use. Every write is
// limited by the worker role to policy/iamap/managed/*.
type PolicyAPI interface {
	ListPolicyVersions(context.Context, *iam.ListPolicyVersionsInput, ...func(*iam.Options)) (*iam.ListPolicyVersionsOutput, error)
	GetPolicyVersion(context.Context, *iam.GetPolicyVersionInput, ...func(*iam.Options)) (*iam.GetPolicyVersionOutput, error)
	CreatePolicyVersion(context.Context, *iam.CreatePolicyVersionInput, ...func(*iam.Options)) (*iam.CreatePolicyVersionOutput, error)
	DeletePolicyVersion(context.Context, *iam.DeletePolicyVersionInput, ...func(*iam.Options)) (*iam.DeletePolicyVersionOutput, error)
	SetDefaultPolicyVersion(context.Context, *iam.SetDefaultPolicyVersionInput, ...func(*iam.Options)) (*iam.SetDefaultPolicyVersionOutput, error)
	ListRoleTags(context.Context, *iam.ListRoleTagsInput, ...func(*iam.Options)) (*iam.ListRoleTagsOutput, error)
}

// MetricsAPI reads Lambda's built-in metrics. GetMetricStatistics only:
// GetMetricData is outside the free tier (CLAUDE.md).
type MetricsAPI interface {
	GetMetricStatistics(context.Context, *cloudwatch.GetMetricStatisticsInput, ...func(*cloudwatch.Options)) (*cloudwatch.GetMetricStatisticsOutput, error)
}

// PRAPI is the GitHub subset the steps use.
type PRAPI interface {
	CommentOnPR(context.Context, int, string) error
	ClosePR(context.Context, int, string, string) error
	OpenRevertPR(context.Context, githubpr.RevertPR) (githubpr.Result, error)
}

// Records is the store subset the steps use.
type Records interface {
	Get(context.Context, string) (store.Rollout, error)
	UpdateStatus(context.Context, string, store.Status, store.Status) error
	SetFields(context.Context, string, map[string]any) error
}

// Engine runs the enforce, watch, rollback, complete, cancel and fail steps.
type Engine struct {
	IAM        PolicyAPI
	CloudTrail observe.CloudTrailAPI
	Metrics    MetricsAPI
	GitHub     PRAPI
	Store      Records
	Config     config.Config
	ConfigPath string // autopilot.yaml in the repo
	Now        func() time.Time
	Log        *slog.Logger
}

func (e *Engine) now() time.Time {
	if e.Now == nil {
		return time.Now().UTC()
	}
	return e.Now().UTC()
}

func (e *Engine) log() *slog.Logger {
	if e.Log == nil {
		return slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return e.Log
}

// checkSafety re-applies the safety rule right before any write.
func (e *Engine) checkSafety(ctx context.Context, r store.Rollout) error {
	if !strings.Contains(r.PolicyArn, ":policy"+generate.ManagedPath) {
		return fmt.Errorf("%w: policy %s is not under %s", ErrUnsafe, r.PolicyArn, generate.ManagedPath)
	}
	tags := map[string]string{}
	var marker *string
	for {
		out, err := e.IAM.ListRoleTags(ctx, &iam.ListRoleTagsInput{RoleName: aws.String(r.RoleName), Marker: marker})
		if err != nil {
			return fmt.Errorf("list tags of %s: %w", r.RoleName, err)
		}
		for _, t := range out.Tags {
			tags[aws.ToString(t.Key)] = aws.ToString(t.Value)
		}
		if !out.IsTruncated || out.Marker == nil {
			break
		}
		marker = out.Marker
	}
	if tags[observe.TagManaged] != "true" {
		return fmt.Errorf("%w: role %s is not tagged %s=true", ErrUnsafe, r.RoleName, observe.TagManaged)
	}
	return nil
}

func (e *Engine) versions(ctx context.Context, arn string) ([]iamtypes.PolicyVersion, error) {
	var out []iamtypes.PolicyVersion
	var marker *string
	for {
		page, err := e.IAM.ListPolicyVersions(ctx, &iam.ListPolicyVersionsInput{PolicyArn: aws.String(arn), Marker: marker})
		if err != nil {
			return nil, fmt.Errorf("list versions of %s: %w", arn, err)
		}
		out = append(out, page.Versions...)
		if !page.IsTruncated || page.Marker == nil {
			break
		}
		marker = page.Marker
	}
	return out, nil
}

// OldestPrunable picks the version to delete when a policy already holds 5:
// the oldest non-default version that is not keep (the rollback target).
// It returns "" if none may be deleted.
func OldestPrunable(versions []iamtypes.PolicyVersion, keep string) string {
	var candidates []iamtypes.PolicyVersion
	for _, v := range versions {
		if v.IsDefaultVersion || aws.ToString(v.VersionId) == keep {
			continue
		}
		candidates = append(candidates, v)
	}
	if len(candidates) == 0 {
		return ""
	}
	sort.Slice(candidates, func(i, j int) bool {
		a, b := aws.ToTime(candidates[i].CreateDate), aws.ToTime(candidates[j].CreateDate)
		if !a.Equal(b) {
			return a.Before(b)
		}
		return aws.ToString(candidates[i].VersionId) < aws.ToString(candidates[j].VersionId)
	})
	return aws.ToString(candidates[0].VersionId)
}

// EnforceResult is the small output the state machine carries on.
type EnforceResult struct {
	PrevVersionID string `json:"prevVersionId"`
	NewVersionID  string `json:"newVersionId"`
}

// Enforce applies an APPROVED proposal as a new default policy version.
//
// It re-checks the safety rule, refuses a stale proposal (the default version
// moved since the proposal was built), prunes the oldest non-default version
// if the policy already holds 5, and records prevVersionId BEFORE creating the
// new version, so a retried invocation reuses the version it already created
// instead of creating a second one and losing the real rollback target.
func (e *Engine) Enforce(ctx context.Context, id string) (EnforceResult, error) {
	r, err := e.Store.Get(ctx, id)
	if err != nil {
		return EnforceResult{}, err
	}
	if r.Status != store.StatusApproved {
		return EnforceResult{}, fmt.Errorf("rollout %s is %s, not APPROVED", id, r.Status)
	}
	if err := e.checkSafety(ctx, r); err != nil {
		return EnforceResult{}, e.fail(ctx, r, err)
	}
	versions, err := e.versions(ctx, r.PolicyArn)
	if err != nil {
		return EnforceResult{}, err
	}
	var def string
	for _, v := range versions {
		if v.IsDefaultVersion {
			def = aws.ToString(v.VersionId)
		}
	}

	// A retry after a successful CreatePolicyVersion: the default already
	// moved off the recorded rollback target. Reuse it.
	if r.PrevVersionID != "" && def != r.PrevVersionID {
		return e.markEnforced(ctx, r, r.PrevVersionID, def)
	}
	if def != r.CurrentVersionID {
		return EnforceResult{}, e.fail(ctx, r, fmt.Errorf("policy %s default version is %s but the proposal was built against %s; re-run the proposal", r.PolicyArn, def, r.CurrentVersionID))
	}
	if err := e.Store.SetFields(ctx, id, map[string]any{"prevVersionId": def}); err != nil {
		return EnforceResult{}, err
	}

	if len(versions) >= maxPolicyVersions {
		victim := OldestPrunable(versions, def)
		if victim == "" {
			return EnforceResult{}, e.fail(ctx, r, fmt.Errorf("policy %s has %d versions and none may be deleted", r.PolicyArn, len(versions)))
		}
		if _, err := e.IAM.DeletePolicyVersion(ctx, &iam.DeletePolicyVersionInput{PolicyArn: aws.String(r.PolicyArn), VersionId: aws.String(victim)}); err != nil {
			return EnforceResult{}, fmt.Errorf("delete version %s of %s: %w", victim, r.PolicyArn, err)
		}
		e.log().Info("pruned policy version", "policy", r.PolicyArn, "version", victim)
	}
	out, err := e.IAM.CreatePolicyVersion(ctx, &iam.CreatePolicyVersionInput{
		PolicyArn: aws.String(r.PolicyArn), PolicyDocument: aws.String(r.ProposedPolicy), SetAsDefault: true,
	})
	if err != nil {
		return EnforceResult{}, fmt.Errorf("create policy version of %s: %w", r.PolicyArn, err)
	}
	return e.markEnforced(ctx, r, def, aws.ToString(out.PolicyVersion.VersionId))
}

func (e *Engine) markEnforced(ctx context.Context, r store.Rollout, prev, next string) (EnforceResult, error) {
	if err := e.Store.UpdateStatus(ctx, r.RolloutID, store.StatusApproved, store.StatusEnforcedWatching); err != nil {
		return EnforceResult{}, err
	}
	if err := e.Store.SetFields(ctx, r.RolloutID, map[string]any{
		"prevVersionId": prev, "newVersionId": next, "enforcedAt": store.Timestamp(e.now()),
	}); err != nil {
		return EnforceResult{}, err
	}
	e.log().Info("enforced", "rollout", r.RolloutID, "policy", r.PolicyArn, "from", prev, "to", next)
	return EnforceResult{PrevVersionID: prev, NewVersionID: next}, nil
}

// WatchResult is one watch iteration.
type WatchResult struct {
	Broken        bool     `json:"broken"`
	DeniedActions []string `json:"deniedActions"`
	ErrorsSum     float64  `json:"errorsSum"`
	Iteration     int      `json:"iteration"`
	Done          bool     `json:"done"`
}

// Watch looks for breakage since enforcedAt with two signals: AccessDenied
// calls by the role in CloudTrail event history (same session-issuer filter
// and denial classification as observe), and the function's Lambda Errors
// metric (Sum > 0). Done means the watch window plus the CloudTrail lag
// buffer has passed without breakage. The first breakage sets detectedAt.
func (e *Engine) Watch(ctx context.Context, id string, iteration int) (WatchResult, error) {
	r, err := e.Store.Get(ctx, id)
	if err != nil {
		return WatchResult{}, err
	}
	if r.Status != store.StatusEnforcedWatching {
		return WatchResult{}, fmt.Errorf("rollout %s is %s, not ENFORCED_WATCHING", id, r.Status)
	}
	enforcedAt, err := time.Parse(time.RFC3339, r.EnforcedAt)
	if err != nil {
		return WatchResult{}, fmt.Errorf("rollout %s enforcedAt %q: %w", id, r.EnforcedAt, err)
	}
	now := e.now()
	res := WatchResult{Iteration: iteration + 1, DeniedActions: []string{}}

	if now.Sub(enforcedAt) >= time.Second {
		obs := observe.New(e.CloudTrail, nil, e.log())
		obs.Now = func() time.Time { return now }
		events, err := obs.Collect(ctx, observe.Role{Name: r.RoleName, ARN: r.RoleArn, FunctionName: r.FunctionName}, enforcedAt, now)
		if err != nil {
			return WatchResult{}, err
		}
		set := map[string]bool{}
		for _, d := range events.Denied {
			set[d.Action] = true
		}
		for a := range set {
			res.DeniedActions = append(res.DeniedActions, a)
		}
		sort.Strings(res.DeniedActions)

		stats, err := e.Metrics.GetMetricStatistics(ctx, &cloudwatch.GetMetricStatisticsInput{
			Namespace:  aws.String("AWS/Lambda"),
			MetricName: aws.String("Errors"),
			Dimensions: []cwtypes.Dimension{{Name: aws.String("FunctionName"), Value: aws.String(r.FunctionName)}},
			StartTime:  aws.Time(enforcedAt),
			EndTime:    aws.Time(now),
			Period:     aws.Int32(60),
			Statistics: []cwtypes.Statistic{cwtypes.StatisticSum},
		})
		if err != nil {
			return WatchResult{}, fmt.Errorf("lambda Errors metric for %s: %w", r.FunctionName, err)
		}
		for _, dp := range stats.Datapoints {
			res.ErrorsSum += aws.ToFloat64(dp.Sum)
		}
	}

	res.Broken = len(res.DeniedActions) > 0 || res.ErrorsSum > 0
	window := time.Duration(e.Config.Watch.Minutes+e.Config.Watch.LagBufferMinutes) * time.Minute
	res.Done = !res.Broken && now.Sub(enforcedAt) >= window

	if res.Broken && r.DetectedAt == "" {
		m := r.Metrics
		m.DetectSeconds = now.Sub(enforcedAt).Seconds()
		m.DeniedActions = res.DeniedActions
		if err := e.Store.SetFields(ctx, id, map[string]any{"detectedAt": store.Timestamp(now), "metrics": m}); err != nil {
			return WatchResult{}, err
		}
	}
	e.log().Info("watch", "rollout", id, "iteration", res.Iteration, "broken", res.Broken, "denied", res.DeniedActions, "errors", res.ErrorsSum, "done", res.Done)
	return res, nil
}

// RollbackResult is the small output of the rollback step.
type RollbackResult struct {
	RestoredVersionID string  `json:"restoredVersionId"`
	RollbackSeconds   float64 `json:"rollbackSeconds"`
	RevertPRURL       string  `json:"revertPrUrl,omitempty"`
	Warning           string  `json:"warning,omitempty"`
}

// Rollback restores prevVersionId as the default version, records the
// timings, comments on the PR and opens the revert PR. Restoring the version
// comes first: GitHub failures after that are reported as a warning and do
// not undo or block the rollback.
func (e *Engine) Rollback(ctx context.Context, id string, denied []string) (RollbackResult, error) {
	r, err := e.Store.Get(ctx, id)
	if err != nil {
		return RollbackResult{}, err
	}
	if r.Status != store.StatusEnforcedWatching {
		return RollbackResult{}, fmt.Errorf("rollout %s is %s, not ENFORCED_WATCHING", id, r.Status)
	}
	if r.PrevVersionID == "" {
		return RollbackResult{}, fmt.Errorf("rollout %s has no prevVersionId to restore", id)
	}
	if !strings.Contains(r.PolicyArn, ":policy"+generate.ManagedPath) {
		return RollbackResult{}, fmt.Errorf("%w: %s", ErrUnsafe, r.PolicyArn)
	}
	if _, err := e.IAM.SetDefaultPolicyVersion(ctx, &iam.SetDefaultPolicyVersionInput{PolicyArn: aws.String(r.PolicyArn), VersionId: aws.String(r.PrevVersionID)}); err != nil {
		return RollbackResult{}, fmt.Errorf("restore %s version %s: %w", r.PolicyArn, r.PrevVersionID, err)
	}
	rolledBack := e.now()
	detected := rolledBack
	if t, err := time.Parse(time.RFC3339, r.DetectedAt); err == nil {
		detected = t
	}
	enforced, _ := time.Parse(time.RFC3339, r.EnforcedAt)
	if denied == nil {
		denied = []string{}
	}
	sort.Strings(denied)
	m := r.Metrics
	m.RollbackSeconds = rolledBack.Sub(detected).Seconds()
	if m.DetectSeconds == 0 && !enforced.IsZero() {
		m.DetectSeconds = detected.Sub(enforced).Seconds()
	}
	m.DeniedActions = denied

	if err := e.Store.UpdateStatus(ctx, id, store.StatusEnforcedWatching, store.StatusRolledBack); err != nil {
		return RollbackResult{}, err
	}
	fields := map[string]any{"rolledBackAt": store.Timestamp(rolledBack), "finishedAt": store.Timestamp(rolledBack), "metrics": m}
	if r.DetectedAt == "" {
		fields["detectedAt"] = store.Timestamp(detected)
	}
	if err := e.Store.SetFields(ctx, id, fields); err != nil {
		return RollbackResult{}, err
	}
	out := RollbackResult{RestoredVersionID: r.PrevVersionID, RollbackSeconds: m.RollbackSeconds}
	e.log().Info("rolled back", "rollout", id, "policy", r.PolicyArn, "restored", r.PrevVersionID, "denied", denied)

	var warnings []string
	cause := "the Lambda `Errors` metric rose above 0, but no `AccessDenied` event could be tied to a specific action, so nothing is added to keepActions"
	if len(denied) > 0 {
		cause = "the role was denied " + codeList(denied)
	}
	comment := fmt.Sprintf("**Rolled back.** After this policy was applied, %s.\n\n"+
		"- Detected %.0f s after enforcement; previous version `%s` restored %.0f s after detection.\n"+
		"- `%s` is the default version again.\n\n%s",
		cause, m.DetectSeconds, r.PrevVersionID, m.RollbackSeconds, r.PrevVersionID, githubpr.RolloutMarker(id))
	if r.PRNumber > 0 && e.GitHub != nil {
		if err := e.GitHub.CommentOnPR(ctx, r.PRNumber, comment); err != nil {
			warnings = append(warnings, err.Error())
		}
	}
	if e.GitHub != nil {
		if pr, err := e.openRevert(ctx, r, denied, m); err != nil {
			warnings = append(warnings, err.Error())
		} else {
			out.RevertPRURL = pr.URL
		}
	}
	out.Warning = strings.Join(warnings, "; ")
	return out, nil
}

func (e *Engine) openRevert(ctx context.Context, r store.Rollout, denied []string, m store.Metrics) (githubpr.Result, error) {
	rc, err := e.Config.RoleOrError(r.RoleName)
	if err != nil {
		return githubpr.Result{}, err
	}
	ver, err := e.IAM.GetPolicyVersion(ctx, &iam.GetPolicyVersionInput{PolicyArn: aws.String(r.PolicyArn), VersionId: aws.String(r.PrevVersionID)})
	if err != nil {
		return githubpr.Result{}, fmt.Errorf("read restored version: %w", err)
	}
	old, err := url.QueryUnescape(aws.ToString(ver.PolicyVersion.Document))
	if err != nil {
		return githubpr.Result{}, err
	}
	if !strings.HasSuffix(old, "\n") {
		old += "\n"
	}
	cfgPath := e.ConfigPath
	if cfgPath == "" {
		cfgPath = config.DefaultPath
	}
	return e.GitHub.OpenRevertPR(ctx, githubpr.RevertPR{
		RolloutID: r.RolloutID, RoleName: r.RoleName, PolicyFile: rc.PolicyFile,
		OldPolicyJSON: []byte(old), KeepActions: denied, ConfigPath: cfgPath,
		Body: githubpr.RenderRevertBody(githubpr.RevertBodyInput{
			RolloutID: r.RolloutID, RoleName: r.RoleName, ProposalPR: r.PRNumber,
			DeniedActions: denied, DetectSeconds: m.DetectSeconds, RollbackSecs: m.RollbackSeconds,
		}),
	})
}

// Complete ends a clean watch: status ENFORCED and a final PR comment. The
// previous version is deliberately kept for a manual rollback.
func (e *Engine) Complete(ctx context.Context, id string) error {
	r, err := e.Store.Get(ctx, id)
	if err != nil {
		return err
	}
	if err := e.Store.UpdateStatus(ctx, id, store.StatusEnforcedWatching, store.StatusEnforced); err != nil {
		return err
	}
	finished := e.now()
	if err := e.Store.SetFields(ctx, id, map[string]any{"finishedAt": store.Timestamp(finished)}); err != nil {
		return err
	}
	if r.PRNumber > 0 && e.GitHub != nil {
		w := e.Config.Watch
		comment := fmt.Sprintf("**Enforced.** `%s` is now version `%s` of `%s` and was watched for %d minutes plus %d minutes of CloudTrail delay with no `AccessDenied` and no Lambda errors.\n\n"+
			"| Metric | Value |\n|---|---|\n| Granted actions | %d → %d (%.1f%% removed) |\n| Observed actions | %d |\n| Shadow mode | %d replayed, %d denied |\n| Enforced at | %s |\n| Finished at | %s |\n\n"+
			"The previous version `%s` is kept. To undo by hand: `aws iam set-default-policy-version --policy-arn %s --version-id %s`\n\n%s",
			r.RoleName, r.NewVersionID, r.PolicyArn, w.Minutes, w.LagBufferMinutes,
			r.Metrics.GrantedBefore, r.Metrics.GrantedAfter, r.Metrics.RemovedPercent, r.Metrics.ObservedActions,
			r.Metrics.ShadowTested, r.Metrics.ShadowDenied, r.EnforcedAt, store.Timestamp(finished),
			r.PrevVersionID, r.PolicyArn, r.PrevVersionID, githubpr.RolloutMarker(id))
		if err := e.GitHub.CommentOnPR(ctx, r.PRNumber, comment); err != nil {
			e.log().Warn("final PR comment failed", "rollout", id, "error", err)
		}
	}
	return nil
}

// Cancel ends a rollout whose PR was closed without merging or whose approval
// timed out: PR_OPEN -> CANCELLED, then comment and close the PR.
func (e *Engine) Cancel(ctx context.Context, id, reason string) error {
	r, err := e.Store.Get(ctx, id)
	if err != nil {
		return err
	}
	if err := e.Store.UpdateStatus(ctx, id, store.StatusPROpen, store.StatusCancelled); err != nil {
		return err
	}
	if err := e.Store.SetFields(ctx, id, map[string]any{"finishedAt": store.Timestamp(e.now())}); err != nil {
		return err
	}
	if r.PRNumber > 0 && e.GitHub != nil {
		comment := fmt.Sprintf("**Cancelled.** %s Nothing was changed in AWS.\n\n%s", reason, githubpr.RolloutMarker(id))
		if err := e.GitHub.ClosePR(ctx, r.PRNumber, r.PRBranch, comment); err != nil {
			e.log().Warn("closing PR failed", "rollout", id, "error", err)
		}
	}
	return nil
}

// MarkFailed moves a non-final rollout to FAILED and says why on its PR.
func (e *Engine) MarkFailed(ctx context.Context, id, cause string) error {
	r, err := e.Store.Get(ctx, id)
	if err != nil {
		return err
	}
	if r.Status.Final() {
		return nil
	}
	return e.fail(ctx, r, errors.New(cause))
}

// fail records FAILED and returns cause (or the store error).
func (e *Engine) fail(ctx context.Context, r store.Rollout, cause error) error {
	if err := e.Store.UpdateStatus(ctx, r.RolloutID, r.Status, store.StatusFailed); err != nil {
		return fmt.Errorf("%v (and could not mark FAILED: %w)", cause, err)
	}
	_ = e.Store.SetFields(ctx, r.RolloutID, map[string]any{"finishedAt": store.Timestamp(e.now())})
	if r.PRNumber > 0 && e.GitHub != nil {
		_ = e.GitHub.CommentOnPR(ctx, r.PRNumber, fmt.Sprintf("**Failed.** %v\n\n%s", cause, githubpr.RolloutMarker(r.RolloutID)))
	}
	return cause
}

func codeList(items []string) string {
	q := make([]string, len(items))
	for i, it := range items {
		q[i] = "`" + it + "`"
	}
	return strings.Join(q, ", ")
}
