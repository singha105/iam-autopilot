// Command worker is the single Lambda binary for the autopilot, deployed
// twice: MODE=worker runs every Step Functions step of a rollout, and
// MODE=approver only handles "approve" calls from the GitHub workflow.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/accessanalyzer"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/sfn"
	"github.com/aws/aws-sdk-go-v2/service/ssm"

	"github.com/singha105/iam-autopilot/internal/catalog"
	"github.com/singha105/iam-autopilot/internal/config"
	"github.com/singha105/iam-autopilot/internal/githubpr"
	"github.com/singha105/iam-autopilot/internal/observe"
	"github.com/singha105/iam-autopilot/internal/rollout"
	"github.com/singha105/iam-autopilot/internal/store"
)

func env(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	d, err := newDeps(context.Background(), logger)
	if err != nil {
		logger.Error("init", "error", err.Error())
		os.Exit(1)
	}
	lambda.Start(func(ctx context.Context, raw json.RawMessage) (any, error) {
		in, err := decode(raw)
		if err != nil {
			return nil, err
		}
		out, err := d.handle(ctx, in)
		if err != nil {
			logger.Error("step failed", "step", in.Step, "error", err.Error())
		}
		return out, err
	})
}

func newDeps(ctx context.Context, logger *slog.Logger) (*deps, error) {
	mode := env("MODE", "")
	if mode != ModeWorker && mode != ModeApprover {
		return nil, fmt.Errorf("MODE must be %q or %q, got %q", ModeWorker, ModeApprover, mode)
	}
	cfg, err := awsconfig.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, err
	}
	owner, repo, ok := strings.Cut(env("GITHUB_REPO", "singha105/iam-autopilot"), "/")
	if !ok {
		return nil, fmt.Errorf("GITHUB_REPO must be owner/repo")
	}
	ghRepo := config.GitHub{Owner: owner, Repo: repo, Branch: env("GITHUB_BRANCH", "main")}
	configPath := env("CONFIG_PATH", config.DefaultPath)
	tokenParam := env("TOKEN_PARAMETER", "/iamap/github/token")

	ssmClient := ssm.NewFromConfig(cfg)
	iamClient := iam.NewFromConfig(cfg)
	ctClient := cloudtrail.NewFromConfig(cfg, func(o *cloudtrail.Options) { o.RetryMaxAttempts = 1 })
	st := store.New(dynamodb.NewFromConfig(cfg), env("TABLE_NAME", store.DefaultTable))

	// The token is read per invocation (cheap, and a rotated token is picked
	// up without a redeploy). It is never logged.
	gh := func(ctx context.Context) (*githubpr.Client, error) {
		out, err := ssmClient.GetParameter(ctx, &ssm.GetParameterInput{Name: aws.String(tokenParam), WithDecryption: aws.Bool(true)})
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", tokenParam, err)
		}
		return githubpr.New(aws.ToString(out.Parameter.Value), ghRepo, "")
	}

	d := &deps{
		mode:  mode,
		now:   func() time.Time { return time.Now().UTC() },
		log:   logger,
		store: st,
		github: func(ctx context.Context) (githubClient, error) {
			c, err := gh(ctx)
			if err != nil {
				return nil, err
			}
			return c, nil
		},
		states: sfn.NewFromConfig(cfg),
	}
	// Config comes from main on GitHub, so a merged revert PR's keepActions
	// apply to the next rollout without a redeploy.
	d.loadConfig = func(ctx context.Context) (config.Config, error) {
		c, err := gh(ctx)
		if err != nil {
			return config.Config{}, err
		}
		return config.LoadFrom(ctx, c, configPath, ghRepo.Branch)
	}
	d.resolve = func(ctx context.Context, role string) (observe.Role, error) {
		return observe.New(ctClient, iamClient, logger).ResolveRole(ctx, role)
	}
	d.plan = func(ctx context.Context, c config.Config, role, id string) (rollout.Plan, error) {
		cat, err := catalog.Default()
		if err != nil {
			return rollout.Plan{}, err
		}
		return rollout.BuildPlan(ctx, rollout.PlanClients{
			CloudTrail: ctClient, IAM: iamClient, PolicyIAM: iamClient,
			Analyzer: accessanalyzer.NewFromConfig(cfg), Simulator: iamClient, Log: logger,
		}, c, cat, role, id, 0)
	}
	d.engine = func(c config.Config, g githubClient) engineSteps {
		return &rollout.Engine{
			IAM: iamClient, CloudTrail: ctClient, Metrics: cloudwatch.NewFromConfig(cfg),
			GitHub: g, Store: st, Config: c, ConfigPath: configPath, Log: logger,
		}
	}
	return d, nil
}
