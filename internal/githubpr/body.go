package githubpr

import (
	"fmt"
	"strings"

	"github.com/singha105/iam-autopilot/internal/generate"
	"github.com/singha105/iam-autopilot/internal/shadow"
)

// BodyInput is what a proposal PR body is rendered from.
type BodyInput struct {
	RolloutID        string
	RoleName         string
	PolicyArn        string
	CurrentVersionID string
	Summary          generate.Summary
	Shadow           shadow.Report
	WatchMinutes     int
	LagBufferMinutes int
}

// Title is "autopilot: tighten <role>: <before> -> <after> permissions".
func Title(s generate.Summary) string {
	return fmt.Sprintf("autopilot: tighten %s: %d -> %d permissions", s.Role, s.GrantedBefore, s.GrantedAfter)
}

// CommitMessage is "autopilot: tighten <role> (-<removed>% permissions)".
func CommitMessage(s generate.Summary) string {
	return fmt.Sprintf("autopilot: tighten %s (-%.1f%% permissions)", s.Role, s.RemovedPercent)
}

// RolloutMarker is the hidden comment tools use to find a PR's rollout.
func RolloutMarker(id string) string { return "<!-- rolloutId: " + id + " -->" }

// RenderPRBody renders the proposal PR body, in this order: one-line summary,
// per-service table, kept-unobservable actions, shadow result, validation,
// warnings, what happens on merge, and the hidden rolloutId marker.
func RenderPRBody(in BodyInput) string {
	s := in.Summary
	var b strings.Builder
	fmt.Fprintf(&b, "**`%s` goes from %d to %d granted actions: %d removed (%.1f%%).**\n\n", s.Role, s.GrantedBefore, s.GrantedAfter, s.RemovedCount, s.RemovedPercent)

	b.WriteString("### Per service\n\n| Service | Before | After | Decided by |\n|---|---:|---:|---|\n")
	for _, r := range s.Services {
		fmt.Fprintf(&b, "| %s | %d | %d | %s |\n", r.Service, r.Before, r.After, r.Rule)
	}
	b.WriteString("\n<details><summary>Every kept action and why</summary>\n\n| Action | Resources | Rule |\n|---|---|---|\n")
	for _, k := range s.Kept {
		fmt.Fprintf(&b, "| `%s` | %s | %s |\n", k.Action, codeList(k.Resources), k.Rule)
	}
	b.WriteString("\n</details>\n")

	b.WriteString("\n### Kept but unobservable\n\n")
	if len(s.KeptUnobservable) == 0 {
		b.WriteString("None.\n")
	} else {
		b.WriteString("CloudTrail event history never records data-plane calls, so these could not be seen. They are kept because the code demonstrably uses the service and its resource (rule R4, ADR-003). Please check them by hand.\n\n")
		for _, k := range s.KeptUnobservable {
			fmt.Fprintf(&b, "- `%s` on %s\n", k.Action, codeList(k.Resources))
		}
	}

	b.WriteString("\n### Shadow mode\n\n")
	fmt.Fprintf(&b, "%d past calls replayed through the IAM policy simulator, %d would be denied.", in.Shadow.Tested, len(in.Shadow.Denied))
	if len(in.Shadow.Skipped) > 0 {
		fmt.Fprintf(&b, " Platform-only actions not replayed (ADR-002): %s.", codeList(in.Shadow.Skipped))
	}
	b.WriteString("\n")
	for _, d := range in.Shadow.Denied {
		fmt.Fprintf(&b, "- **would be denied:** `%s` on `%s` (%s)\n", d.Action, d.Resource, d.Decision)
	}
	for _, w := range in.Shadow.Warnings {
		fmt.Fprintf(&b, "- %s\n", w)
	}

	b.WriteString("\n### Validation (Access Analyzer ValidatePolicy)\n\n")
	if len(s.Validation) == 0 {
		b.WriteString("No findings.\n")
	}
	for _, f := range s.Validation {
		fmt.Fprintf(&b, "- **%s** `%s`: %s\n", f.Type, f.IssueCode, f.Message)
	}

	if len(s.Warnings) > 0 {
		b.WriteString("\n### Warnings\n\n")
		for _, w := range s.Warnings {
			fmt.Fprintf(&b, "- %s\n", w)
		}
	}

	b.WriteString("\n### What happens when you merge\n\n")
	fmt.Fprintf(&b, "1. The autopilot applies this file as a new version of `%s`. The current version (`%s`) is kept as the rollback target.\n", in.PolicyArn, in.CurrentVersionID)
	fmt.Fprintf(&b, "2. It watches the role for %d minutes (plus %d minutes for CloudTrail delay) for `AccessDenied` events and Lambda errors.\n", in.WatchMinutes, in.LagBufferMinutes)
	b.WriteString("3. If anything is denied, it restores the previous version within seconds and opens a revert PR that adds the denied action to this role's `keepActions`.\n")
	b.WriteString("\nClose this PR without merging to reject the proposal; nothing changes in AWS.\n")
	fmt.Fprintf(&b, "\n%s\n", RolloutMarker(in.RolloutID))
	return b.String()
}

// RevertBodyInput is what a revert PR body is rendered from.
type RevertBodyInput struct {
	RolloutID     string
	RoleName      string
	ProposalPR    int
	DeniedActions []string
	DetectSeconds float64
	RollbackSecs  float64
}

// RenderRevertBody explains an automatic rollback.
func RenderRevertBody(in RevertBodyInput) string {
	var b strings.Builder
	fmt.Fprintf(&b, "**The autopilot rolled back `%s`** after the tightened policy from #%d denied a call the role needed.\n\n", in.RoleName, in.ProposalPR)
	fmt.Fprintf(&b, "- Denied: %s\n", codeList(in.DeniedActions))
	fmt.Fprintf(&b, "- Detected after %.0f s; previous policy version restored in %.0f s.\n\n", in.DetectSeconds, in.RollbackSecs)
	b.WriteString("This PR makes `main` match AWS again: it restores the policy file and adds the denied actions to the role's `keepActions` in `autopilot.yaml`, so the next proposal keeps them.\n")
	fmt.Fprintf(&b, "\n%s\n", RolloutMarker(in.RolloutID))
	return b.String()
}

func codeList(items []string) string {
	q := make([]string, len(items))
	for i, it := range items {
		q[i] = "`" + it + "`"
	}
	return strings.Join(q, ", ")
}
