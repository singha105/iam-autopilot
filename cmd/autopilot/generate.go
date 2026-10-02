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
	"path/filepath"
	"strings"
	"time"

	"github.com/singha105/iam-autopilot/internal/catalog"
	"github.com/singha105/iam-autopilot/internal/config"
	"github.com/singha105/iam-autopilot/internal/generate"
	"github.com/singha105/iam-autopilot/internal/observe"
)

// profileFlags are shared by generate and shadow: either read a saved profile
// or observe the role now.
type profileFlags struct {
	role        string
	profilePath string
	days        int
	region      string
	configPath  string
}

func (p *profileFlags) register(fs *flag.FlagSet) {
	fs.StringVar(&p.role, "role", "", "IAM role name (required; must be tagged autopilot:managed=true and listed in autopilot.yaml)")
	fs.StringVar(&p.profilePath, "profile", "", "usage profile JSON from `autopilot observe`; if empty, observe the role now")
	fs.IntVar(&p.days, "days", 0, "observation window when observing now (default: the role's observationDays in autopilot.yaml)")
	fs.StringVar(&p.region, "region", "us-east-1", "AWS region")
	fs.StringVar(&p.configPath, "config", config.DefaultPath, "autopilot config file")
}

func (p *profileFlags) validate(stderr io.Writer, cmd string) bool {
	switch {
	case p.role == "":
		fmt.Fprintf(stderr, "%s: --role is required\n", cmd)
	case p.profilePath != "" && p.days != 0:
		fmt.Fprintf(stderr, "%s: use --profile or --days, not both\n", cmd)
	case p.days < 0:
		fmt.Fprintf(stderr, "%s: --days must be positive\n", cmd)
	default:
		return true
	}
	return false
}

// loadProfile reads --profile, or observes the role over --days (or the
// role's observationDays, or 90).
func loadProfile(ctx context.Context, p profileFlags, cfg config.Config, clients awsClients, stderr io.Writer) (observe.Profile, error) {
	if p.profilePath != "" {
		b, err := os.ReadFile(p.profilePath)
		if err != nil {
			return observe.Profile{}, err
		}
		var prof observe.Profile
		if err := json.Unmarshal(b, &prof); err != nil {
			return observe.Profile{}, fmt.Errorf("profile %s: %w", p.profilePath, err)
		}
		if prof.RoleName != p.role {
			return observe.Profile{}, fmt.Errorf("profile %s is for role %s, not %s", p.profilePath, prof.RoleName, p.role)
		}
		return prof, nil
	}
	days := p.days
	if days == 0 {
		if r, ok := cfg.Role(p.role); ok && r.ObservationDays > 0 {
			days = r.ObservationDays
		} else {
			days = 90
		}
	}
	o := observe.New(clients.CloudTrail, clients.IAM, slog.New(slog.NewTextHandler(stderr, nil)))
	end := now().UTC().Truncate(time.Second)
	o.Now = func() time.Time { return end }
	return o.BuildProfile(ctx, p.role, end.Add(-time.Duration(days)*24*time.Hour), end)
}

func runGenerate(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	var pf profileFlags
	var outDir, record string
	fs := flag.NewFlagSet("generate", flag.ContinueOnError)
	fs.SetOutput(stderr)
	pf.register(fs)
	fs.StringVar(&outDir, "out-dir", "out", "directory for <role>/proposed-policy.json, summary.json and summary.md")
	fs.StringVar(&record, "record", "", "also save the raw current-policy API responses, redacted, into this directory")
	fs.Usage = func() {
		fmt.Fprint(fs.Output(), "Usage: autopilot generate --role <name> [--profile profile.json | --days N] [--out-dir out/]\n\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return err
		}
		return errUsage
	}
	if !pf.validate(stderr, "generate") {
		fs.Usage()
		return errUsage
	}

	cfg, err := config.Load(pf.configPath)
	if err != nil {
		return err
	}
	cat, err := catalog.Default()
	if err != nil {
		return err
	}
	clients, err := loadClients(ctx, pf.region)
	if err != nil {
		return err
	}
	prof, err := loadProfile(ctx, pf, cfg, clients, stderr)
	if err != nil {
		return err
	}

	var policyIAM generate.IAMAPI = clients.PolicyIAM
	if record != "" {
		account, err := clients.AccountID(ctx)
		if err != nil {
			return fmt.Errorf("get account ID for redaction: %w", err)
		}
		policyIAM = generate.RecordingIAM{Inner: policyIAM, Rec: &observe.Recorder{Dir: record, AccountID: account}}
	}
	current, err := generate.CurrentPolicy(ctx, policyIAM, pf.role)
	if err != nil {
		return err
	}
	res, err := generate.Generate(current.Document, prof, cfg, cat)
	if err != nil {
		return err
	}
	findings, err := generate.Validate(ctx, clients.Analyzer, res.Policy)
	if err != nil {
		return err
	}
	res.Summary.AddValidation(findings)

	dir := filepath.Join(outDir, pf.role)
	summaryJSON, _ := json.MarshalIndent(res.Summary, "", "  ")
	profileJSON, err := prof.Encode()
	if err != nil {
		return err
	}
	currentJSON, err := current.Document.Encode()
	if err != nil {
		return err
	}
	for name, b := range map[string][]byte{
		"proposed-policy.json": res.PolicyJSON,
		"summary.json":         append(summaryJSON, '\n'),
		"summary.md":           []byte(res.Summary.Markdown()),
		"profile.json":         profileJSON,
		"current-policy.json":  currentJSON,
	} {
		if err := writeFile(filepath.Join(dir, name), b); err != nil {
			return err
		}
	}

	s := res.Summary
	fmt.Fprintf(stdout, "%s (%s, version %s)\n", pf.role, current.ARN, current.VersionID)
	fmt.Fprintf(stdout, "  %d -> %d actions granted: %d removed (%.1f%%)\n", s.GrantedBefore, s.GrantedAfter, s.RemovedCount, s.RemovedPercent)
	if len(s.KeptUnobservable) > 0 {
		var names []string
		for _, k := range s.KeptUnobservable {
			names = append(names, k.Action)
		}
		fmt.Fprintf(stdout, "  kept-unobservable (R4): %s\n", strings.Join(names, ", "))
	}
	fmt.Fprintf(stdout, "  validation findings: %d, warnings: %d\n", len(s.Validation), len(s.Warnings))
	fmt.Fprintf(stdout, "  wrote %s/{proposed-policy.json,summary.json,summary.md,profile.json,current-policy.json}\n", dir)
	return generate.CheckFindings(findings)
}
