package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/singha105/iam-autopilot/internal/config"
	"github.com/singha105/iam-autopilot/internal/generate"
	"github.com/singha105/iam-autopilot/internal/policy"
	"github.com/singha105/iam-autopilot/internal/shadow"
)

// errDenied makes `autopilot shadow` exit non-zero when a past call would be denied.
var errDenied = errors.New("would-be denials")

func runShadow(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	var pf profileFlags
	var policyPath string
	fs := flag.NewFlagSet("shadow", flag.ContinueOnError)
	fs.SetOutput(stderr)
	pf.register(fs)
	fs.StringVar(&policyPath, "policy", "", "proposed policy JSON to test (required)")
	fs.Usage = func() {
		fmt.Fprint(fs.Output(), "Usage: autopilot shadow --role <name> --policy out/<role>/proposed-policy.json [--profile profile.json | --days N]\n\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return err
		}
		return errUsage
	}
	if !pf.validate(stderr, "shadow") {
		fs.Usage()
		return errUsage
	}
	if policyPath == "" {
		fmt.Fprintln(stderr, "shadow: --policy is required")
		fs.Usage()
		return errUsage
	}

	raw, err := os.ReadFile(policyPath)
	if err != nil {
		return err
	}
	proposed, err := policy.Parse(raw)
	if err != nil {
		return err
	}
	cfg, err := config.Load(pf.configPath)
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
	current, err := generate.CurrentPolicy(ctx, clients.PolicyIAM, pf.role)
	if err != nil {
		return err
	}

	rep, err := shadow.New(clients.Simulator).ReplayWithSelfTest(ctx, proposed, current.Document, prof)
	if err != nil {
		return err
	}
	printReport(stdout, pf.role, policyPath, rep)
	if len(rep.Denied) > 0 {
		return fmt.Errorf("%d past call(s) would be denied by %s: %w", len(rep.Denied), policyPath, errDenied)
	}
	return nil
}

func printReport(w io.Writer, role, policyPath string, rep shadow.Report) {
	fmt.Fprintf(w, "Shadow replay for %s of %s (IAM policy simulator)\n", role, policyPath)
	fmt.Fprintf(w, "  tested %d, allowed %d, denied %d\n", rep.Tested, rep.Allowed, len(rep.Denied))
	for _, d := range rep.Denied {
		fmt.Fprintf(w, "  DENIED  %s on %s (%s)\n", d.Action, d.Resource, d.Decision)
	}
	if len(rep.Skipped) > 0 {
		fmt.Fprintf(w, "  skipped platform-only actions (ADR-002): %s\n", strings.Join(rep.Skipped, ", "))
	}
	if len(rep.Warnings) == 0 {
		fmt.Fprintln(w, "  self-test: the current policy allows every call in the test set")
	}
	for _, warning := range rep.Warnings {
		fmt.Fprintf(w, "  warning: %s\n", warning)
	}
}
