package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/singha105/iam-autopilot/internal/config"
	"github.com/singha105/iam-autopilot/internal/githubpr"
	"github.com/singha105/iam-autopilot/internal/observe"
	"github.com/singha105/iam-autopilot/internal/rollout"
	"github.com/singha105/iam-autopilot/internal/store"
)

// Modes. One binary, two functions, two IAM roles.
const (
	ModeWorker   = "worker"
	ModeApprover = "approver"
)

// State is the small object the state machine carries between steps. Big
// data (policies, summaries, reports) lives in the DynamoDB record; Step
// Functions payloads are limited to 256 KB.
type State struct {
	RolloutID     string     `json:"rolloutId,omitempty"`
	RoleName      string     `json:"roleName"`
	ShadowDenied  int        `json:"shadowDenied"`
	NothingToDo   bool       `json:"nothingToDo"`
	PRNumber      int        `json:"prNumber,omitempty"`
	PRURL         string     `json:"prUrl,omitempty"`
	PollSeconds   int        `json:"pollSeconds"`
	Iteration     int        `json:"iteration"`
	Broken        bool       `json:"broken"`
	Done          bool       `json:"done"`
	DeniedActions []string   `json:"deniedActions"`
	ErrorsSum     float64    `json:"errorsSum"`
	Error         *StepError `json:"error,omitempty"` // set by a Catch (ResultPath $.error)
}

// StepError is what a Step Functions Catch puts at $.error.
type StepError struct {
	Error string `json:"Error"`
	Cause string `json:"Cause"`
}

// Input is the Lambda event. The state machine sends {"step", "state",
// "taskToken"}; the approve workflow sends {"step", "rolloutId", "prNumber"}.
type Input struct {
	Step      string `json:"step"`
	State     *State `json:"state,omitempty"`
	TaskToken string `json:"taskToken,omitempty"`
	RolloutID string `json:"rolloutId,omitempty"`
	RoleName  string `json:"roleName,omitempty"`
	PRNumber  int    `json:"prNumber,omitempty"`
}

// githubClient is what the steps need from GitHub.
type githubClient interface {
	rollout.PRAPI
	rollout.MergeChecker
	OpenPolicyPR(context.Context, githubpr.PolicyPR) (githubpr.Result, error)
}

// recordStore is what the steps need from DynamoDB.
type recordStore interface {
	rollout.Records
	Create(context.Context, store.Rollout) error
	ActiveForRole(context.Context, string) ([]store.Rollout, error)
}

// engineSteps are the rollout.Engine methods (an interface for tests).
type engineSteps interface {
	Enforce(context.Context, string) (rollout.EnforceResult, error)
	Watch(context.Context, string, int) (rollout.WatchResult, error)
	Rollback(context.Context, string, []string) (rollout.RollbackResult, error)
	Complete(context.Context, string) error
	Cancel(context.Context, string, string) error
	MarkFailed(context.Context, string, string) error
}

// deps are built once per cold start (see main.go) and replaced in tests.
type deps struct {
	mode       string
	now        func() time.Time
	log        *slog.Logger
	store      recordStore
	loadConfig func(context.Context) (config.Config, error)
	github     func(context.Context) (githubClient, error)
	resolve    func(context.Context, string) (observe.Role, error)
	plan       func(context.Context, config.Config, string, string) (rollout.Plan, error)
	engine     func(config.Config, githubClient) engineSteps
	states     rollout.StatesAPI
}

var errRefused = errors.New("step not allowed in this mode")

// handle dispatches one step. The approver accepts only "approve"; the
// worker accepts every other step and never "approve".
func (d *deps) handle(ctx context.Context, in Input) (any, error) {
	d.log.Info("step", "mode", d.mode, "step", in.Step)
	if d.mode == ModeApprover {
		if in.Step != "approve" {
			return nil, fmt.Errorf("%w: the approver only accepts step \"approve\", got %q", errRefused, in.Step)
		}
		return d.approve(ctx, in)
	}
	if in.Step == "approve" {
		return nil, fmt.Errorf("%w: the worker never approves", errRefused)
	}

	s := State{RoleName: in.RoleName, DeniedActions: []string{}}
	if in.State != nil {
		s = *in.State
		if s.DeniedActions == nil {
			s.DeniedActions = []string{}
		}
	}
	if in.Step != "start" && s.RolloutID == "" {
		return nil, fmt.Errorf("step %q needs state.rolloutId", in.Step)
	}

	switch in.Step {
	case "start":
		return d.start(ctx, s)
	case "observe_generate_shadow":
		return d.observeGenerateShadow(ctx, s)
	case "propose":
		return d.propose(ctx, s)
	case "await":
		return d.await(ctx, s, in.TaskToken)
	}

	cfg, err := d.loadConfig(ctx)
	if err != nil {
		return nil, err
	}
	gh, err := d.github(ctx)
	if err != nil {
		return nil, err
	}
	e := d.engine(cfg, gh)
	switch in.Step {
	case "enforce":
		if _, err := e.Enforce(ctx, s.RolloutID); err != nil {
			return nil, err
		}
		s.Iteration = 0
		return s, nil
	case "watch":
		w, err := e.Watch(ctx, s.RolloutID, s.Iteration)
		if err != nil {
			return nil, err
		}
		s.Broken, s.Done, s.Iteration, s.DeniedActions, s.ErrorsSum = w.Broken, w.Done, w.Iteration, w.DeniedActions, w.ErrorsSum
		return s, nil
	case "rollback":
		res, err := e.Rollback(ctx, s.RolloutID, s.DeniedActions)
		if err != nil {
			return nil, err
		}
		if res.Warning != "" {
			d.log.Warn("rollback done with warnings", "rollout", s.RolloutID, "warning", res.Warning)
		}
		return s, nil
	case "complete":
		return s, e.Complete(ctx, s.RolloutID)
	case "cancel":
		return s, e.Cancel(ctx, s.RolloutID, cancelReason(s.Error))
	case "mark_failed":
		cause := "the rollout failed"
		if s.Error != nil {
			cause = strings.TrimSpace(s.Error.Error + ": " + s.Error.Cause)
		}
		if err := e.MarkFailed(ctx, s.RolloutID, cause); err != nil {
			d.log.Warn("marked FAILED", "rollout", s.RolloutID, "cause", err)
		}
		return s, nil
	}
	return nil, fmt.Errorf("unknown step %q", in.Step)
}

func cancelReason(e *StepError) string {
	if e == nil {
		return "The rollout was cancelled."
	}
	switch e.Error {
	case rollout.ErrorPRClosed:
		return "The PR was closed without merging."
	case "States.Timeout":
		return "No decision within 7 days, so the proposal expired."
	}
	return "The approval step ended with " + e.Error + "."
}

// start: safety checks, one rollout per role, create the record.
func (d *deps) start(ctx context.Context, s State) (State, error) {
	if s.RoleName == "" {
		return s, errors.New("start needs roleName")
	}
	cfg, err := d.loadConfig(ctx)
	if err != nil {
		return s, err
	}
	if _, err := cfg.RoleOrError(s.RoleName); err != nil {
		return s, err
	}
	role, err := d.resolve(ctx, s.RoleName) // refuses roles not tagged autopilot:managed=true
	if err != nil {
		return s, err
	}
	active, err := d.store.ActiveForRole(ctx, s.RoleName)
	if err != nil {
		return s, err
	}
	if len(active) > 0 {
		return s, fmt.Errorf("rollout %s for %s is still %s", active[0].RolloutID, s.RoleName, active[0].Status)
	}
	now := d.now()
	s.RolloutID = store.NewID(s.RoleName, now)
	s.PollSeconds = cfg.Watch.PollSeconds
	if s.PollSeconds <= 0 {
		s.PollSeconds = 300
	}
	err = d.store.Create(ctx, store.Rollout{
		RolloutID: s.RolloutID, RoleName: role.Name, RoleArn: role.ARN, FunctionName: role.FunctionName,
		Status: store.StatusObserving, CreatedAt: store.Timestamp(now), Metrics: store.Metrics{DeniedActions: []string{}},
	})
	return s, err
}

// observeGenerateShadow builds the plan and stores it. A blocking validation
// finding is an error, so the state machine's Catch marks the rollout FAILED.
func (d *deps) observeGenerateShadow(ctx context.Context, s State) (State, error) {
	cfg, err := d.loadConfig(ctx)
	if err != nil {
		return s, err
	}
	p, err := d.plan(ctx, cfg, s.RoleName, s.RolloutID)
	if err != nil {
		return s, err
	}
	if p.ValidationErr != nil {
		return s, p.ValidationErr
	}
	r := p.Rollout
	fields := map[string]any{
		"roleArn": r.RoleArn, "functionName": r.FunctionName, "policyArn": r.PolicyArn, "currentVersionId": r.CurrentVersionID,
		"proposedPolicy": r.ProposedPolicy, "summary": r.Summary, "shadowReport": r.ShadowReport, "metrics": r.Metrics,
	}
	if r.FinishedAt != "" {
		fields["finishedAt"] = r.FinishedAt
	}
	if err := d.store.SetFields(ctx, s.RolloutID, fields); err != nil {
		return s, err
	}
	if r.Status == store.StatusShadowFailed || r.Status == store.StatusNothingToDo {
		if err := d.store.UpdateStatus(ctx, s.RolloutID, store.StatusObserving, r.Status); err != nil {
			return s, err
		}
	}
	s.ShadowDenied = r.Metrics.ShadowDenied
	s.NothingToDo = r.Status == store.StatusNothingToDo
	return s, nil
}

// propose opens the PR. A retried invocation that finds a PR already
// recorded does not open a second one.
func (d *deps) propose(ctx context.Context, s State) (State, error) {
	r, err := d.store.Get(ctx, s.RolloutID)
	if err != nil {
		return s, err
	}
	if r.PRNumber > 0 {
		s.PRNumber, s.PRURL = r.PRNumber, r.PRURL
		return s, nil
	}
	cfg, err := d.loadConfig(ctx)
	if err != nil {
		return s, err
	}
	rc, err := cfg.RoleOrError(r.RoleName)
	if err != nil {
		return s, err
	}
	body, summary, err := rollout.BodyFromRecord(r, cfg)
	if err != nil {
		return s, err
	}
	gh, err := d.github(ctx)
	if err != nil {
		return s, err
	}
	pr, err := gh.OpenPolicyPR(ctx, githubpr.PolicyPR{
		RolloutID: r.RolloutID, PolicyFile: rc.PolicyFile, PolicyJSON: []byte(r.ProposedPolicy),
		Title: githubpr.Title(summary), CommitMessage: githubpr.CommitMessage(summary), Body: body,
	})
	if err != nil {
		return s, err
	}
	if err := d.store.SetFields(ctx, s.RolloutID, map[string]any{"prNumber": pr.Number, "prUrl": pr.URL, "prBranch": pr.Branch}); err != nil {
		return s, err
	}
	if err := d.store.UpdateStatus(ctx, s.RolloutID, store.StatusObserving, store.StatusPROpen); err != nil {
		return s, err
	}
	d.log.Info("PR opened", "rollout", s.RolloutID, "pr", pr.URL)
	s.PRNumber, s.PRURL = pr.Number, pr.URL
	return s, nil
}

// await stores the task token and returns at once; the execution then waits
// until the approver calls SendTaskSuccess or SendTaskFailure.
func (d *deps) await(ctx context.Context, s State, token string) (State, error) {
	if token == "" {
		return s, errors.New("await needs taskToken")
	}
	r, err := d.store.Get(ctx, s.RolloutID)
	if err != nil {
		return s, err
	}
	if err := d.store.SetFields(ctx, s.RolloutID, map[string]any{"taskToken": token}); err != nil {
		return s, err
	}
	if r.Status == store.StatusObserving {
		if err := d.store.UpdateStatus(ctx, s.RolloutID, store.StatusObserving, store.StatusPROpen); err != nil {
			return s, err
		}
	} else if r.Status != store.StatusPROpen {
		return s, fmt.Errorf("rollout %s is %s, cannot wait for approval", s.RolloutID, r.Status)
	}
	return s, nil
}

func (d *deps) approve(ctx context.Context, in Input) (rollout.ApproveResult, error) {
	if in.RolloutID == "" || in.PRNumber <= 0 {
		return rollout.ApproveResult{}, errors.New("approve needs rolloutId and prNumber")
	}
	gh, err := d.github(ctx)
	if err != nil {
		return rollout.ApproveResult{}, err
	}
	a := &rollout.Approver{Store: d.store, GitHub: gh, States: d.states}
	return a.Approve(ctx, in.RolloutID, in.PRNumber, store.Timestamp(d.now()))
}

// decode keeps unknown fields out: a typo in the ASL fails loudly.
func decode(raw json.RawMessage) (Input, error) {
	var in Input
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil {
		return in, fmt.Errorf("bad input: %w", err)
	}
	return in, nil
}
