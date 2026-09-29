// Command demo-quarterly is a demo Lambda with a rarely used code path.
//
// A normal run reads one SSM parameter. A run with the payload
// {"mode":"quarter-end"} also lists every parameter under the quarterly path.
// The traffic script never sends quarter-end, so the autopilot will not see
// ssm:GetParametersByPath and will remove it; Day 6 then triggers quarter-end
// to show the automatic rollback and the keep-list PR.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"

	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
)

const (
	appName             = "iamap-demo-quarterly"
	defaultScheduleName = "/iamap/demo/quarterly/schedule"
	defaultQuarterlyDir = "/iamap/demo/quarterly/"
	modeQuarterEnd      = "quarter-end"
)

type ssmAPI interface {
	GetParameter(context.Context, *ssm.GetParameterInput, ...func(*ssm.Options)) (*ssm.GetParameterOutput, error)
	GetParametersByPath(context.Context, *ssm.GetParametersByPathInput, ...func(*ssm.Options)) (*ssm.GetParametersByPathOutput, error)
}

// Event is the Lambda input. An empty payload means a normal run.
type Event struct {
	Mode string `json:"mode"`
}

// Summary is the Lambda's JSON response.
type Summary struct {
	Mode       string `json:"mode"`
	Schedule   string `json:"schedule"`
	Parameters int    `json:"parameters,omitempty"`
}

type app struct {
	ssm      ssmAPI
	schedule string
	path     string
	log      *slog.Logger
}

func (a *app) handle(ctx context.Context, ev Event) (Summary, error) {
	s := Summary{Mode: "normal"}
	if ev.Mode == modeQuarterEnd {
		s.Mode = modeQuarterEnd
	}
	var errs []error
	fail := func(action string, err error) {
		a.log.Error("aws call failed", "app", appName, "mode", s.Mode, "action", action, "error", err.Error())
		errs = append(errs, fmt.Errorf("%s: %w", action, err))
	}

	if out, err := a.ssm.GetParameter(ctx, &ssm.GetParameterInput{Name: aws.String(a.schedule)}); err != nil {
		fail("ssm:GetParameter", err)
	} else if out.Parameter != nil {
		s.Schedule = aws.ToString(out.Parameter.Value)
	}

	if s.Mode == modeQuarterEnd {
		if out, err := a.ssm.GetParametersByPath(ctx, &ssm.GetParametersByPathInput{Path: aws.String(a.path)}); err != nil {
			fail("ssm:GetParametersByPath", err)
		} else {
			s.Parameters = len(out.Parameters)
		}
	}

	if len(errs) > 0 {
		return s, errors.Join(errs...)
	}
	a.log.Info("quarterly run complete", "app", appName, "summary", s)
	return s, nil
}

func envOr(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	cfg, err := config.LoadDefaultConfig(context.Background())
	if err != nil {
		logger.Error("load aws config", "app", appName, "error", err.Error())
		os.Exit(1)
	}
	a := &app{
		ssm:      ssm.NewFromConfig(cfg),
		schedule: envOr("SCHEDULE_PARAMETER", defaultScheduleName),
		path:     envOr("QUARTERLY_PATH", defaultQuarterlyDir),
		log:      logger,
	}
	lambda.Start(a.handle)
}
