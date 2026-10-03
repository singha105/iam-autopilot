package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

	"github.com/singha105/iam-autopilot/internal/store"
)

// runReport lists every rollout. --short prints one line each (id, role,
// status, PR, removed %); the default adds timings, versions and denials.
func runReport(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	var region, table string
	var short bool
	fs := flag.NewFlagSet("report", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.BoolVar(&short, "short", false, "one line per rollout")
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
	all, err := clients.Rollouts(table).ListAll(ctx)
	if err != nil {
		return err
	}
	writeReport(stdout, all, short)
	return nil
}

func writeReport(w io.Writer, all []store.Rollout, short bool) {
	if len(all) == 0 {
		fmt.Fprintln(w, "no rollouts")
		return
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "ROLLOUT\tROLE\tSTATUS\tPR\tREMOVED")
	for _, r := range all {
		pr := "-"
		if r.PRNumber > 0 {
			pr = fmt.Sprintf("#%d", r.PRNumber)
		}
		removed := "-"
		if r.Metrics.GrantedBefore > 0 {
			removed = fmt.Sprintf("%.1f%% (%d -> %d)", r.Metrics.RemovedPercent, r.Metrics.GrantedBefore, r.Metrics.GrantedAfter)
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", r.RolloutID, r.RoleName, r.Status, pr, removed)
	}
	tw.Flush()
	if short {
		return
	}
	for _, r := range all {
		var lines []string
		add := func(label, v string) {
			if v != "" {
				lines = append(lines, fmt.Sprintf("    %-14s %s", label, v))
			}
		}
		add("pr", r.PRURL)
		add("versions", strings.Trim(r.PrevVersionID+" -> "+r.NewVersionID, " ->"))
		add("created", r.CreatedAt)
		add("approved", r.ApprovedAt)
		add("enforced", r.EnforcedAt)
		add("detected", r.DetectedAt)
		add("rolled back", r.RolledBackAt)
		add("finished", r.FinishedAt)
		if r.Metrics.DetectSeconds > 0 || r.Metrics.RollbackSeconds > 0 {
			add("timings", fmt.Sprintf("detect %.0f s, rollback %.0f s", r.Metrics.DetectSeconds, r.Metrics.RollbackSeconds))
		}
		if len(r.Metrics.DeniedActions) > 0 {
			add("denied", strings.Join(r.Metrics.DeniedActions, ", "))
		}
		if r.Metrics.ShadowTested > 0 {
			add("shadow", fmt.Sprintf("%d replayed, %d denied", r.Metrics.ShadowTested, r.Metrics.ShadowDenied))
		}
		fmt.Fprintf(w, "\n%s\n%s\n", r.RolloutID, strings.Join(lines, "\n"))
	}
}
