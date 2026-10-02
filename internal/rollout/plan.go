package rollout

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"time"

	"github.com/singha105/iam-autopilot/internal/catalog"
	"github.com/singha105/iam-autopilot/internal/config"
	"github.com/singha105/iam-autopilot/internal/generate"
	"github.com/singha105/iam-autopilot/internal/githubpr"
	"github.com/singha105/iam-autopilot/internal/observe"
	"github.com/singha105/iam-autopilot/internal/shadow"
	"github.com/singha105/iam-autopilot/internal/store"
)

// PlanClients are the read-only AWS clients a plan needs.
type PlanClients struct {
	CloudTrail observe.CloudTrailAPI
	IAM        observe.IAMAPI
	PolicyIAM  generate.IAMAPI
	Analyzer   generate.AccessAnalyzerAPI
	Simulator  shadow.SimulatorAPI
	Log        *slog.Logger
	Now        func() time.Time
}

// Plan is a decided proposal: the rollout record to write and everything
// needed to explain it.
type Plan struct {
	Rollout       store.Rollout
	Role          observe.Role
	Current       generate.ManagedPolicy
	Result        generate.Result
	Shadow        shadow.Report
	Findings      []generate.Finding
	ValidationErr error // non-nil means ERROR/SECURITY_WARNING findings
	PolicyFile    string
	Body          string
}

// BuildPlan runs observe -> generate -> validate -> shadow for one role and
// decides the rollout status: FAILED (blocking validation findings),
// SHADOW_FAILED (a past call would be denied), NOTHING_TO_DO (same access),
// or PR_OPEN. It is read-only; the caller writes the record and opens the PR.
// days 0 means the role's observationDays (or 90).
func BuildPlan(ctx context.Context, c PlanClients, cfg config.Config, cat *catalog.Catalog, roleName, rolloutID string, days int) (Plan, error) {
	if c.Log == nil {
		c.Log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	if c.Now == nil {
		c.Now = time.Now
	}
	rc, err := cfg.RoleOrError(roleName)
	if err != nil {
		return Plan{}, err
	}
	if rc.PolicyFile == "" {
		return Plan{}, fmt.Errorf("role %s has no policyFile in autopilot.yaml; a PR would not know which file to edit", roleName)
	}
	if days == 0 {
		days = rc.ObservationDays
	}
	if days == 0 {
		days = 90
	}

	obs := observe.New(c.CloudTrail, c.IAM, c.Log)
	end := c.Now().UTC().Truncate(time.Second)
	obs.Now = func() time.Time { return end }
	target, err := obs.ResolveRole(ctx, roleName) // refuses unmanaged roles
	if err != nil {
		return Plan{}, err
	}
	current, err := generate.CurrentPolicy(ctx, c.PolicyIAM, roleName)
	if err != nil {
		return Plan{}, err
	}
	prof, err := obs.BuildProfile(ctx, roleName, end.Add(-time.Duration(days)*24*time.Hour), end)
	if err != nil {
		return Plan{}, err
	}

	res, err := generate.Generate(current.Document, prof, cfg, cat)
	if err != nil {
		return Plan{}, err
	}
	findings, err := generate.Validate(ctx, c.Analyzer, res.Policy)
	if err != nil {
		return Plan{}, err
	}
	res.Summary.AddValidation(findings)
	rep, err := shadow.New(c.Simulator).ReplayWithSelfTest(ctx, res.Policy, current.Document, prof)
	if err != nil {
		return Plan{}, err
	}
	same, err := generate.SameAccess(current.Document, res.Policy, cat)
	if err != nil {
		return Plan{}, err
	}

	p := Plan{
		Role: target, Current: current, Result: res, Shadow: rep, Findings: findings,
		ValidationErr: generate.CheckFindings(findings), PolicyFile: rc.PolicyFile,
	}
	p.Rollout = newRecord(rolloutID, target, current, res, rep, prof, end)
	switch {
	case p.ValidationErr != nil:
		p.Rollout.Status = store.StatusFailed
	case len(rep.Denied) > 0:
		p.Rollout.Status = store.StatusShadowFailed
	case same:
		p.Rollout.Status = store.StatusNothingToDo
	default:
		p.Rollout.Status = store.StatusPROpen
	}
	if p.Rollout.Status.Final() {
		p.Rollout.FinishedAt = store.Timestamp(end)
	}
	p.Body = githubpr.RenderPRBody(githubpr.BodyInput{
		RolloutID: rolloutID, RoleName: roleName, PolicyArn: current.ARN, CurrentVersionID: current.VersionID,
		Summary: res.Summary, Shadow: rep, WatchMinutes: cfg.Watch.Minutes, LagBufferMinutes: cfg.Watch.LagBufferMinutes,
	})
	return p, nil
}

func newRecord(id string, target observe.Role, current generate.ManagedPolicy, res generate.Result, rep shadow.Report, prof observe.Profile, at time.Time) store.Rollout {
	summary, _ := json.Marshal(res.Summary)
	report, _ := json.Marshal(rep)
	actions := map[string]bool{}
	for _, c := range prof.ObservedCalls {
		actions[c.Action] = true
	}
	denied := []string{}
	for _, d := range rep.Denied {
		denied = append(denied, d.Action)
	}
	return store.Rollout{
		RolloutID: id, RoleName: target.Name, RoleArn: target.ARN, FunctionName: target.FunctionName,
		PolicyArn: current.ARN, CurrentVersionID: current.VersionID,
		ProposedPolicy: string(res.PolicyJSON), Summary: string(summary), ShadowReport: string(report),
		CreatedAt: store.Timestamp(at),
		Metrics: store.Metrics{
			GrantedBefore: res.Summary.GrantedBefore, GrantedAfter: res.Summary.GrantedAfter, RemovedPercent: res.Summary.RemovedPercent,
			ObservedActions: len(actions), ShadowTested: rep.Tested, ShadowDenied: len(rep.Denied), DeniedActions: denied,
		},
	}
}

// BodyFromRecord re-renders a stored proposal's PR body from the record's
// summary and shadow report JSON (the worker's propose step runs in a later
// Lambda invocation than the plan).
func BodyFromRecord(r store.Rollout, cfg config.Config) (string, generate.Summary, error) {
	var s generate.Summary
	if err := json.Unmarshal([]byte(r.Summary), &s); err != nil {
		return "", s, fmt.Errorf("rollout %s summary: %w", r.RolloutID, err)
	}
	var rep shadow.Report
	if err := json.Unmarshal([]byte(r.ShadowReport), &rep); err != nil {
		return "", s, fmt.Errorf("rollout %s shadow report: %w", r.RolloutID, err)
	}
	return githubpr.RenderPRBody(githubpr.BodyInput{
		RolloutID: r.RolloutID, RoleName: r.RoleName, PolicyArn: r.PolicyArn, CurrentVersionID: r.CurrentVersionID,
		Summary: s, Shadow: rep, WatchMinutes: cfg.Watch.Minutes, LagBufferMinutes: cfg.Watch.LagBufferMinutes,
	}), s, nil
}
