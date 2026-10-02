package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ssm"

	"github.com/singha105/iam-autopilot/internal/catalog"
	"github.com/singha105/iam-autopilot/internal/config"
	"github.com/singha105/iam-autopilot/internal/generate"
	"github.com/singha105/iam-autopilot/internal/githubpr"
	"github.com/singha105/iam-autopilot/internal/observe"
	"github.com/singha105/iam-autopilot/internal/shadow"
	"github.com/singha105/iam-autopilot/internal/store"
)

// tokenParameter is the hand-created SSM SecureString holding the GitHub token.
const tokenParameter = "/iamap/github/token"

// rolloutStore is what the CLI needs from internal/store.
type rolloutStore interface {
	Create(context.Context, store.Rollout) error
	Get(context.Context, string) (store.Rollout, error)
	UpdateStatus(context.Context, string, store.Status, store.Status) error
	SetFields(context.Context, string, map[string]any) error
	ActiveForRole(context.Context, string) ([]store.Rollout, error)
	ListAll(context.Context) ([]store.Rollout, error)
}

// prClient is what the CLI needs from internal/githubpr.
type prClient interface {
	OpenPolicyPR(context.Context, githubpr.PolicyPR) (githubpr.Result, error)
	ClosePR(context.Context, int, string, string) error
}

// ssmAPI reads the GitHub token parameter.
type ssmAPI interface {
	GetParameter(context.Context, *ssm.GetParameterInput, ...func(*ssm.Options)) (*ssm.GetParameterOutput, error)
}

// githubToken returns GITHUB_TOKEN if set, otherwise the SSM SecureString.
// The token is never printed.
func githubToken(ctx context.Context, c awsClients) (string, error) {
	if t := os.Getenv("GITHUB_TOKEN"); t != "" {
		return t, nil
	}
	if c.SSM == nil {
		return "", githubpr.ErrNoToken
	}
	out, err := c.SSM.GetParameter(ctx, &ssm.GetParameterInput{Name: aws.String(tokenParameter), WithDecryption: aws.Bool(true)})
	if err != nil {
		return "", fmt.Errorf("%w (%v)", githubpr.ErrNoToken, err)
	}
	if out.Parameter == nil || aws.ToString(out.Parameter.Value) == "" {
		return "", githubpr.ErrNoToken
	}
	return aws.ToString(out.Parameter.Value), nil
}

// newPRClient builds the GitHub client; tests replace it.
var newPRClient = func(ctx context.Context, c awsClients, repo config.GitHub) (prClient, error) {
	token, err := githubToken(ctx, c)
	if err != nil {
		return nil, err
	}
	return githubpr.New(token, repo, "")
}

// errShadowFailed and errProposalFailed make `propose` exit 1.
var (
	errShadowFailed   = errors.New("shadow mode found would-be denials")
	errProposalFailed = errors.New("proposal failed")
)

func runPropose(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	var role, configPath, region, table string
	var days int
	var dryRun bool
	fs := flag.NewFlagSet("propose", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.StringVar(&role, "role", "", "IAM role name (required)")
	fs.IntVar(&days, "days", 0, "observation window (default: the role's observationDays)")
	fs.BoolVar(&dryRun, "dry-run", false, "do everything except writing to DynamoDB and GitHub; print the PR body")
	fs.StringVar(&configPath, "config", config.DefaultPath, "autopilot config file")
	fs.StringVar(&region, "region", "us-east-1", "AWS region")
	fs.StringVar(&table, "table", store.DefaultTable, "rollouts table")
	fs.Usage = func() {
		fmt.Fprint(fs.Output(), "Usage: autopilot propose --role <name> [--days N] [--dry-run]\n\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return err
		}
		return errUsage
	}
	if role == "" || days < 0 || fs.NArg() > 0 {
		fmt.Fprintln(stderr, "propose: --role is required (and --days must be positive)")
		fs.Usage()
		return errUsage
	}

	cfg, err := config.Load(configPath)
	if err != nil {
		return err
	}
	rc, err := cfg.RoleOrError(role)
	if err != nil {
		return err
	}
	if rc.PolicyFile == "" {
		return fmt.Errorf("role %s has no policyFile in %s; the PR would not know which file to edit", role, configPath)
	}
	cat, err := catalog.Default()
	if err != nil {
		return err
	}
	clients, err := loadClients(ctx, region)
	if err != nil {
		return err
	}
	rollouts := clients.Rollouts(table)

	// 1. One rollout per role at a time.
	active, err := rollouts.ActiveForRole(ctx, role)
	if err != nil {
		return err
	}
	if len(active) > 0 {
		return fmt.Errorf("rollout %s for %s is still %s; finish or cancel it first", active[0].RolloutID, role, active[0].Status)
	}

	// 2. Resolve (refuses unmanaged roles), read the current policy, observe.
	logger := slog.New(slog.NewTextHandler(stderr, nil))
	target, err := observe.New(clients.CloudTrail, clients.IAM, logger).ResolveRole(ctx, role)
	if err != nil {
		return err
	}
	current, err := generate.CurrentPolicy(ctx, clients.PolicyIAM, role)
	if err != nil {
		return err
	}
	prof, err := loadProfile(ctx, profileFlags{role: role, days: days, region: region, configPath: configPath}, cfg, clients, stderr)
	if err != nil {
		return err
	}

	// 3. Generate, validate, shadow.
	res, err := generate.Generate(current.Document, prof, cfg, cat)
	if err != nil {
		return err
	}
	findings, err := generate.Validate(ctx, clients.Analyzer, res.Policy)
	if err != nil {
		return err
	}
	res.Summary.AddValidation(findings)
	validationErr := generate.CheckFindings(findings)
	rep, err := shadow.New(clients.Simulator).ReplayWithSelfTest(ctx, res.Policy, current.Document, prof)
	if err != nil {
		return err
	}
	same, err := generate.SameAccess(current.Document, res.Policy, cat)
	if err != nil {
		return err
	}

	at := now().UTC()
	r := buildRollout(store.NewID(role, at), target, current, res, rep, prof, at)
	body := githubpr.RenderPRBody(githubpr.BodyInput{
		RolloutID: r.RolloutID, RoleName: role, PolicyArn: current.ARN, CurrentVersionID: current.VersionID,
		Summary: res.Summary, Shadow: rep, WatchMinutes: cfg.Watch.Minutes, LagBufferMinutes: cfg.Watch.LagBufferMinutes,
	})

	switch {
	case validationErr != nil:
		r.Status = store.StatusFailed
	case len(rep.Denied) > 0:
		r.Status = store.StatusShadowFailed
	case same:
		r.Status = store.StatusNothingToDo
	default:
		r.Status = store.StatusPROpen
	}
	if r.Status.Final() {
		r.FinishedAt = store.Timestamp(at)
	}

	fmt.Fprintf(stdout, "Rollout %s: %s\n", r.RolloutID, r.Status)
	fmt.Fprintf(stdout, "  %d -> %d actions granted (%.1f%% removed); shadow %d tested, %d denied; %d validation finding(s)\n",
		res.Summary.GrantedBefore, res.Summary.GrantedAfter, res.Summary.RemovedPercent, rep.Tested, len(rep.Denied), len(findings))

	if dryRun {
		fmt.Fprintf(stdout, "\n--dry-run: nothing written to DynamoDB or GitHub. The PR would be:\n\n")
		fmt.Fprintf(stdout, "Branch: autopilot/%s\nFile:   %s\nCommit: %s\nTitle:  %s\n\n%s", r.RolloutID, rc.PolicyFile, githubpr.CommitMessage(res.Summary), githubpr.Title(res.Summary), body)
		return outcomeErr(r.Status, validationErr, rep)
	}

	if err := rollouts.Create(ctx, r); err != nil {
		return err
	}
	if r.Status != store.StatusPROpen {
		if r.Status == store.StatusShadowFailed {
			printReport(stdout, role, "the proposal", rep)
		}
		return outcomeErr(r.Status, validationErr, rep)
	}

	// 4. Open the PR; on failure the record moves to FAILED so it is not left active.
	fail := func(cause error) error {
		if err := rollouts.UpdateStatus(ctx, r.RolloutID, store.StatusPROpen, store.StatusFailed); err != nil {
			fmt.Fprintf(stderr, "warning: could not mark %s FAILED: %v\n", r.RolloutID, err)
		}
		_ = rollouts.SetFields(ctx, r.RolloutID, map[string]any{"finishedAt": store.Timestamp(now())})
		return cause
	}
	gh, err := newPRClient(ctx, clients, cfg.GitHub)
	if err != nil {
		return fail(err)
	}
	pr, err := gh.OpenPolicyPR(ctx, githubpr.PolicyPR{
		RolloutID: r.RolloutID, PolicyFile: rc.PolicyFile, PolicyJSON: res.PolicyJSON,
		Title: githubpr.Title(res.Summary), CommitMessage: githubpr.CommitMessage(res.Summary), Body: body,
	})
	if err != nil {
		return fail(err)
	}
	if err := rollouts.SetFields(ctx, r.RolloutID, map[string]any{"prNumber": pr.Number, "prUrl": pr.URL, "prBranch": pr.Branch}); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "  opened %s\n", pr.URL)
	return nil
}

func outcomeErr(s store.Status, validationErr error, rep shadow.Report) error {
	switch s {
	case store.StatusFailed:
		return fmt.Errorf("%w: %v", errProposalFailed, validationErr)
	case store.StatusShadowFailed:
		return fmt.Errorf("%w: %d past call(s) would be denied", errShadowFailed, len(rep.Denied))
	}
	return nil
}

func buildRollout(id string, target observe.Role, current generate.ManagedPolicy, res generate.Result, rep shadow.Report, prof observe.Profile, at time.Time) store.Rollout {
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

func runCancel(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	var id, region, table, configPath, reason string
	fs := flag.NewFlagSet("cancel", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.StringVar(&id, "rollout", "", "rollout ID (required)")
	fs.StringVar(&reason, "reason", "Cancelled from the CLI without merging; nothing was changed in AWS.", "comment left on the PR")
	fs.StringVar(&configPath, "config", config.DefaultPath, "autopilot config file")
	fs.StringVar(&region, "region", "us-east-1", "AWS region")
	fs.StringVar(&table, "table", store.DefaultTable, "rollouts table")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return err
		}
		return errUsage
	}
	if id == "" {
		fmt.Fprintln(stderr, "cancel: --rollout is required")
		return errUsage
	}
	cfg, err := config.Load(configPath)
	if err != nil {
		return err
	}
	clients, err := loadClients(ctx, region)
	if err != nil {
		return err
	}
	rollouts := clients.Rollouts(table)
	r, err := rollouts.Get(ctx, id)
	if err != nil {
		return err
	}
	if r.Status != store.StatusPROpen {
		return fmt.Errorf("rollout %s is %s; only a PR_OPEN rollout can be cancelled", id, r.Status)
	}
	// Claim the transition first: if the PR was approved in the meantime this
	// fails and the PR is left alone.
	if err := rollouts.UpdateStatus(ctx, id, store.StatusPROpen, store.StatusCancelled); err != nil {
		return err
	}
	if err := rollouts.SetFields(ctx, id, map[string]any{"finishedAt": store.Timestamp(now())}); err != nil {
		return err
	}
	if r.PRNumber == 0 {
		fmt.Fprintf(stdout, "Rollout %s: CANCELLED (it had no PR)\n", id)
		return nil
	}
	gh, err := newPRClient(ctx, clients, cfg.GitHub)
	if err != nil {
		return fmt.Errorf("rollout %s is CANCELLED but PR #%d is still open (close it by hand): %w", id, r.PRNumber, err)
	}
	comment := fmt.Sprintf("**Cancelled.** %s\n\n%s", reason, githubpr.RolloutMarker(id))
	if err := gh.ClosePR(ctx, r.PRNumber, r.PRBranch, comment); err != nil {
		return fmt.Errorf("rollout %s is CANCELLED but closing PR #%d failed (close it by hand): %w", id, r.PRNumber, err)
	}
	fmt.Fprintf(stdout, "Rollout %s: CANCELLED; closed %s and deleted branch %s\n", id, r.PRURL, r.PRBranch)
	return nil
}

func runStatus(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	var id, region, table string
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.StringVar(&id, "rollout", "", "show one rollout in full (default: list all)")
	fs.StringVar(&region, "region", "us-east-1", "AWS region")
	fs.StringVar(&table, "table", store.DefaultTable, "rollouts table")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return err
		}
		return errUsage
	}
	clients, err := loadClients(ctx, region)
	if err != nil {
		return err
	}
	rollouts := clients.Rollouts(table)
	if id != "" {
		r, err := rollouts.Get(ctx, id)
		if err != nil {
			return err
		}
		// Long JSON payloads are summarised; the full item is in DynamoDB.
		r.ProposedPolicy = fmt.Sprintf("(%d bytes)", len(r.ProposedPolicy))
		r.Summary = fmt.Sprintf("(%d bytes)", len(r.Summary))
		r.ShadowReport = fmt.Sprintf("(%d bytes)", len(r.ShadowReport))
		b, _ := json.MarshalIndent(r, "", "  ")
		fmt.Fprintln(stdout, string(b))
		return nil
	}
	all, err := rollouts.ListAll(ctx)
	if err != nil {
		return err
	}
	if len(all) == 0 {
		fmt.Fprintln(stdout, "no rollouts")
	}
	for _, r := range all {
		pr := ""
		if r.PRNumber > 0 {
			pr = fmt.Sprintf("PR #%d", r.PRNumber)
		}
		fmt.Fprintf(stdout, "%-52s %-18s %5d -> %-4d %s\n", r.RolloutID, r.Status, r.Metrics.GrantedBefore, r.Metrics.GrantedAfter, strings.TrimSpace(pr))
	}
	return nil
}
