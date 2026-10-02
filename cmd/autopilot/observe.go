package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/accessanalyzer"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"github.com/singha105/iam-autopilot/internal/generate"
	"github.com/singha105/iam-autopilot/internal/observe"
	"github.com/singha105/iam-autopilot/internal/shadow"
)

type observeOptions struct {
	role   string
	days   int
	region string
	out    string
	record string
}

func parseObserveFlags(args []string, stderr io.Writer) (observeOptions, error) {
	var o observeOptions
	fs := flag.NewFlagSet("observe", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.StringVar(&o.role, "role", "", "IAM role name to observe (required; must be tagged autopilot:managed=true)")
	fs.IntVar(&o.days, "days", 90, "observation window in days, ending now (event history keeps at most 90)")
	fs.StringVar(&o.region, "region", "us-east-1", "AWS region whose CloudTrail event history to read")
	fs.StringVar(&o.out, "out", "", "where to write the profile JSON (default build/profiles/<role>.json)")
	fs.StringVar(&o.record, "record", "", "also save every raw API response, redacted, into this directory as test fixtures")
	fs.Usage = func() {
		fmt.Fprint(fs.Output(), "Usage: autopilot observe --role <roleName> [--days N] [--region us-east-1] [--out profile.json] [--record dir]\n\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return o, err
		}
		return o, errUsage
	}
	switch {
	case o.role == "":
		fmt.Fprintln(stderr, "observe: --role is required")
	case o.days < 1:
		fmt.Fprintln(stderr, "observe: --days must be at least 1")
	case fs.NArg() > 0:
		fmt.Fprintf(stderr, "observe: unexpected arguments: %s\n", strings.Join(fs.Args(), " "))
	default:
		if o.out == "" {
			o.out = filepath.Join("build", "profiles", o.role+".json")
		}
		return o, nil
	}
	fs.Usage()
	return o, errUsage
}

// awsClients are the clients observe needs. AccountID is only called when
// recording fixtures, to know which ID to redact.
type awsClients struct {
	CloudTrail observe.CloudTrailAPI
	IAM        observe.IAMAPI
	PolicyIAM  generate.IAMAPI
	Simulator  shadow.SimulatorAPI
	Analyzer   generate.AccessAnalyzerAPI
	AccountID  func(context.Context) (string, error)
}

// loadClients builds real clients from the default credential chain (so a
// short-lived `aws login` session works). Tests replace it.
var loadClients = func(ctx context.Context, region string) (awsClients, error) {
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		return awsClients{}, fmt.Errorf("load AWS config: %w", err)
	}
	stsClient := sts.NewFromConfig(cfg)
	iamClient := iam.NewFromConfig(cfg)
	return awsClients{
		// The observer does its own rate limiting and throttling retries, so the
		// SDK's retryer is turned off for CloudTrail to keep attempts predictable.
		CloudTrail: cloudtrail.NewFromConfig(cfg, func(o *cloudtrail.Options) { o.RetryMaxAttempts = 1 }),
		IAM:        iamClient,
		PolicyIAM:  iamClient,
		Simulator:  iamClient,
		Analyzer:   accessanalyzer.NewFromConfig(cfg),
		AccountID: func(ctx context.Context) (string, error) {
			out, err := stsClient.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
			if err != nil {
				return "", err
			}
			return aws.ToString(out.Account), nil
		},
	}, nil
}

// now is the CLI's clock; tests pin it.
var now = time.Now

// fixtureMeta is saved next to recorded fixtures so a replay can rebuild the
// exact same window.
type fixtureMeta struct {
	RoleName string    `json:"roleName"`
	Days     int       `json:"days"`
	Now      time.Time `json:"now"`
}

func runObserve(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	opts, err := parseObserveFlags(args, stderr)
	if err != nil {
		return err
	}
	clients, err := loadClients(ctx, opts.region)
	if err != nil {
		return err
	}

	var ct observe.CloudTrailAPI = clients.CloudTrail
	var iamClient observe.IAMAPI = clients.IAM
	if opts.record != "" {
		account, err := clients.AccountID(ctx)
		if err != nil {
			return fmt.Errorf("get account ID for redaction: %w", err)
		}
		rec := &observe.Recorder{Dir: opts.record, AccountID: account}
		ct = observe.RecordingCloudTrail{Inner: ct, Rec: rec}
		iamClient = observe.RecordingIAM{Inner: iamClient, Rec: rec}
	}

	o := observe.New(ct, iamClient, slog.New(slog.NewTextHandler(stderr, nil)))
	end := now().UTC().Truncate(time.Second)
	o.Now = func() time.Time { return end }
	start := end.Add(-time.Duration(opts.days) * 24 * time.Hour)

	p, err := o.BuildProfile(ctx, opts.role, start, end)
	if err != nil {
		return err
	}
	b, err := p.Encode()
	if err != nil {
		return err
	}
	if err := writeFile(opts.out, b); err != nil {
		return err
	}
	if opts.record != "" {
		meta, _ := json.MarshalIndent(fixtureMeta{RoleName: opts.role, Days: opts.days, Now: end}, "", "  ")
		if err := writeFile(filepath.Join(opts.record, "meta.json"), append(meta, '\n')); err != nil {
			return err
		}
	}
	printSummary(stdout, p, opts.out)
	return nil
}

func writeFile(path string, b []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o644)
}

// printSummary writes a short human summary of a profile.
func printSummary(w io.Writer, p observe.Profile, outPath string) {
	ts := func(t time.Time) string { return t.UTC().Format(time.RFC3339) }
	fmt.Fprintf(w, "Role      %s (function %s)\n", p.RoleName, p.FunctionName)
	fmt.Fprintf(w, "Window    %s -> %s\n", ts(p.Window.Start), ts(p.Window.End))
	fmt.Fprintf(w, "Scanned   %d event(s) in %d page(s)\n\n", p.Stats.EventsScanned, p.Stats.PagesFetched)

	actions := map[string]bool{}
	for _, c := range p.ObservedCalls {
		actions[c.Action] = true
	}
	fmt.Fprintf(w, "Observed actions (%d), from CloudTrail event history:\n", len(actions))
	if len(p.ObservedCalls) == 0 {
		fmt.Fprintln(w, "  none")
	} else {
		tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
		for _, c := range p.ObservedCalls {
			mode := "write"
			if c.ReadOnly {
				mode = "read"
			}
			fmt.Fprintf(tw, "  %s\t%s\tx%d\t%s\tlast %s\n", c.Action, c.Resource, c.Count, mode, ts(c.LastSeen))
		}
		tw.Flush()
	}

	accessed := p.AccessedServices()
	var unused []string
	for _, s := range p.ServicesAccessed {
		if s.LastAuthenticated == nil {
			unused = append(unused, s.Namespace)
		}
	}
	fmt.Fprintf(w, "\nServices accessed (%d of %d granted), from IAM Access Advisor:\n", len(accessed), len(p.ServicesAccessed))
	for _, s := range p.ServicesAccessed {
		if s.LastAuthenticated == nil {
			continue
		}
		line := fmt.Sprintf("  %s\tlast %s", s.Namespace, ts(*s.LastAuthenticated))
		if len(s.TrackedActions) > 0 {
			names := make([]string, len(s.TrackedActions))
			for i, a := range s.TrackedActions {
				names[i] = a.Action
			}
			line += "\ttracked: " + strings.Join(names, ", ")
		}
		fmt.Fprintln(w, line)
	}
	if len(accessed) == 0 {
		fmt.Fprintln(w, "  none (Access Advisor can lag by up to about 4 hours)")
	}
	if len(unused) > 0 {
		fmt.Fprintf(w, "  not used in window: %s\n", strings.Join(unused, ", "))
	}

	fmt.Fprintf(w, "\nDenied calls (%d):\n", len(p.DeniedCalls))
	if len(p.DeniedCalls) == 0 {
		fmt.Fprintln(w, "  none")
	}
	for _, d := range p.DeniedCalls {
		fmt.Fprintf(w, "  %s  %s  %s  %s\n", ts(d.Time), d.Action, d.Resource, d.ErrorCode)
	}

	if len(p.Warnings) > 0 {
		fmt.Fprintf(w, "\nWarnings (%d):\n", len(p.Warnings))
		for _, warning := range p.Warnings {
			fmt.Fprintf(w, "  - %s\n", warning)
		}
	}
	fmt.Fprintf(w, "\nProfile written to %s\n", outPath)
}
