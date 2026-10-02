package githubpr

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/singha105/iam-autopilot/internal/generate"
	"github.com/singha105/iam-autopilot/internal/shadow"
)

const (
	oldPolicy = "{\"Statement\":[{\"Action\":\"ssm:*\",\"Effect\":\"Allow\",\"Resource\":\"*\"}],\"Version\":\"2012-10-17\"}\n"
	newPolicy = "{\n  \"Statement\": [\n    {\n      \"Action\": [\n        \"ssm:GetParameter\"\n      ],\n      \"Effect\": \"Allow\",\n      \"Resource\": [\n        \"*\"\n      ],\n      \"Sid\": \"Ssm0\"\n    }\n  ],\n  \"Version\": \"2012-10-17\"\n}\n"
	rollout   = "iamap-demo-quarterly-role-20261002T050000Z"
	policyF   = "policies/demo/quarterly.json"
)

func repoFiles(t *testing.T) map[string]string {
	t.Helper()
	cfg, err := os.ReadFile("../../autopilot.yaml")
	if err != nil {
		t.Fatal(err)
	}
	return map[string]string{policyF: oldPolicy, "autopilot.yaml": string(cfg)}
}

func summary() generate.Summary {
	return generate.Summary{
		Role: "iamap-demo-quarterly-role", GrantedBefore: 532, GrantedAfter: 1, RemovedCount: 531, RemovedPercent: 99.8,
		Services: []generate.ServiceSummary{
			{Service: "ec2", Before: 194, After: 0, Rule: "R1 (unused)"},
			{Service: "ssm", Before: 164, After: 1, Rule: "R2,R5"},
		},
		Kept:             []generate.KeptAction{{Action: "ssm:GetParameter", Resources: []string{"arn:aws:ssm:us-east-1:123456789012:parameter/iamap/demo/quarterly/schedule"}, Rule: "R2,R5"}},
		KeptUnobservable: []generate.KeptAction{},
		Validation:       []generate.Finding{},
		Warnings:         []string{},
	}
}

func TestOpenPolicyPR(t *testing.T) {
	f, c := newFakeGitHub(t, repoFiles(t))
	s := summary()
	res, err := c.OpenPolicyPR(context.Background(), PolicyPR{
		RolloutID: rollout, PolicyFile: policyF, PolicyJSON: []byte(newPolicy),
		Title: Title(s), CommitMessage: CommitMessage(s), Body: "body " + RolloutMarker(rollout),
	})
	if err != nil {
		t.Fatal(err)
	}
	branch := "autopilot/" + rollout
	if res.Number != 7 || res.URL != "https://github.com/o/r/pull/7" || res.Branch != branch {
		t.Errorf("result = %+v", res)
	}
	if got := f.branches[branch][policyF]; got != newPolicy {
		t.Errorf("policy on branch = %q", got)
	}
	if f.branches["main"][policyF] != oldPolicy {
		t.Error("main must not change")
	}
	if len(f.commits) != 1 || f.commits[0].message != "autopilot: tighten iamap-demo-quarterly-role (-99.8% permissions)" {
		t.Errorf("commits = %+v", f.commits)
	}
	pr := f.pulls[7]
	if pr.Title != "autopilot: tighten iamap-demo-quarterly-role: 532 -> 1 permissions" || pr.Head != branch || pr.Base != "main" {
		t.Errorf("pr = %+v", pr)
	}
	if !f.labels[Label] || len(f.issueLbl[7]) != 1 || f.issueLbl[7][0] != Label {
		t.Errorf("label not created and applied: labels=%v issue=%v", f.labels, f.issueLbl)
	}
	if f.auth[0] != "Bearer test-token" {
		t.Errorf("Authorization = %q", f.auth[0])
	}

	// A second PR reuses the existing label instead of creating it again.
	if _, err := c.OpenPolicyPR(context.Background(), PolicyPR{RolloutID: rollout + "-2", PolicyFile: policyF, PolicyJSON: []byte(newPolicy), Title: "t", CommitMessage: "m", Body: "b"}); err != nil {
		t.Fatal(err)
	}
	// Opening the same rollout twice fails: the branch already exists.
	if _, err := c.OpenPolicyPR(context.Background(), PolicyPR{RolloutID: rollout, PolicyFile: policyF, PolicyJSON: []byte(newPolicy)}); err == nil {
		t.Error("reusing a rollout branch must fail")
	}
}

func TestOpenPolicyPRCreatesAMissingFile(t *testing.T) {
	f, c := newFakeGitHub(t, map[string]string{})
	if _, err := c.OpenPolicyPR(context.Background(), PolicyPR{RolloutID: rollout, PolicyFile: "policies/demo/new.json", PolicyJSON: []byte(newPolicy), Title: "t", CommitMessage: "m", Body: "b"}); err != nil {
		t.Fatal(err)
	}
	if f.branches["autopilot/"+rollout]["policies/demo/new.json"] != newPolicy {
		t.Error("new file not created")
	}
}

func TestOpenRevertPR(t *testing.T) {
	f, c := newFakeGitHub(t, repoFiles(t))
	// Pretend main already has the tightened policy (the merged proposal).
	f.branches["main"][policyF] = newPolicy
	res, err := c.OpenRevertPR(context.Background(), RevertPR{
		RolloutID: rollout, RoleName: "iamap-demo-quarterly-role", PolicyFile: policyF,
		OldPolicyJSON: []byte(oldPolicy), KeepActions: []string{"ssm:GetParametersByPath"}, ConfigPath: "autopilot.yaml",
		Body: RenderRevertBody(RevertBodyInput{RolloutID: rollout, RoleName: "iamap-demo-quarterly-role", ProposalPR: 7, DeniedActions: []string{"ssm:GetParametersByPath"}, DetectSeconds: 64, RollbackSecs: 2}),
	})
	if err != nil {
		t.Fatal(err)
	}
	branch := "autopilot-revert/" + rollout
	if res.Branch != branch {
		t.Errorf("branch = %s", res.Branch)
	}
	if f.branches[branch][policyF] != oldPolicy {
		t.Error("old policy not restored on the revert branch")
	}
	cfg := f.branches[branch]["autopilot.yaml"]
	if !strings.Contains(cfg, "  - name: iamap-demo-quarterly-role\n    policyFile: policies/demo/quarterly.json\n    observationDays: 1\n    keepActions: [ssm:GetParametersByPath]") {
		t.Errorf("keepActions not added to the quarterly role:\n%s", cfg)
	}
	if len(f.commits) != 2 {
		t.Errorf("commits = %+v, want policy + config", f.commits)
	}
	pr := f.pulls[res.Number]
	if !strings.Contains(pr.Title, "revert iamap-demo-quarterly-role") || !strings.Contains(pr.Body, RolloutMarker(rollout)) || !strings.Contains(pr.Body, "#7") {
		t.Errorf("revert PR = %+v", pr)
	}
}

func TestCommentCloseAndIsMerged(t *testing.T) {
	f, c := newFakeGitHub(t, repoFiles(t))
	res, err := c.OpenPolicyPR(context.Background(), PolicyPR{RolloutID: rollout, PolicyFile: policyF, PolicyJSON: []byte(newPolicy), Title: "t", CommitMessage: "m", Body: "b"})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := c.CommentOnPR(ctx, res.Number, "watching"); err != nil {
		t.Fatal(err)
	}
	info, err := c.IsMerged(ctx, res.Number)
	if err != nil || info.Merged || info.State != "open" {
		t.Errorf("IsMerged = %+v, %v", info, err)
	}

	f.pulls[res.Number].Merged, f.pulls[res.Number].MergedBy, f.pulls[res.Number].MergedAt = true, "singha105", "2026-10-02T05:10:00Z"
	info, err = c.IsMerged(ctx, res.Number)
	if err != nil || !info.Merged || info.MergedBy != "singha105" || !info.MergedAt.Equal(time.Date(2026, 10, 2, 5, 10, 0, 0, time.UTC)) {
		t.Errorf("IsMerged after merge = %+v, %v", info, err)
	}

	f.pulls[res.Number].Merged = false
	if err := c.ClosePR(ctx, res.Number, res.Branch, "cancelled"); err != nil {
		t.Fatal(err)
	}
	if f.pulls[res.Number].State != "closed" || f.branches[res.Branch] != nil {
		t.Errorf("PR not closed or branch not deleted: state=%s", f.pulls[res.Number].State)
	}
	if got := f.comments[res.Number]; len(got) != 2 || got[1] != "cancelled" {
		t.Errorf("comments = %v", got)
	}
}

func TestFetchFile(t *testing.T) {
	_, c := newFakeGitHub(t, repoFiles(t))
	b, err := c.FetchFile(context.Background(), "autopilot.yaml", "main")
	if err != nil || !strings.Contains(string(b), "iamap-demo-inventory-role") {
		t.Errorf("FetchFile = %d bytes, %v", len(b), err)
	}
	if b, err := c.FetchFile(context.Background(), "missing.yaml", "main"); err != nil || b != nil {
		t.Errorf("missing file = %v, %v", b, err)
	}
}

func TestRenderPRBody(t *testing.T) {
	s := summary()
	s.KeptUnobservable = []generate.KeptAction{{Action: "dynamodb:GetItem", Resources: []string{"arn:aws:dynamodb:us-east-1:123456789012:table/t"}, Rule: "R4"}}
	s.Validation = []generate.Finding{{Type: "SUGGESTION", IssueCode: "EMPTY_ARRAY_RESOURCE", Message: "m"}}
	body := RenderPRBody(BodyInput{
		RolloutID: rollout, RoleName: s.Role, PolicyArn: "arn:aws:iam::123456789012:policy/iamap/managed/p", CurrentVersionID: "v1",
		Summary: s, Shadow: shadow.Report{Tested: 5, Allowed: 5, Skipped: []string{"logs:CreateLogStream"}}, WatchMinutes: 30, LagBufferMinutes: 15,
	})
	order := []string{
		"goes from 532 to 1 granted actions: 531 removed (99.8%)",
		"| ec2 | 194 | 0 | R1 (unused) |",
		"### Kept but unobservable", "`dynamodb:GetItem`",
		"### Shadow mode", "5 past calls replayed through the IAM policy simulator, 0 would be denied.",
		"### Validation", "**SUGGESTION** `EMPTY_ARRAY_RESOURCE`",
		"### What happens when you merge", "watches the role for 30 minutes", "restores the previous version within seconds",
		RolloutMarker(rollout),
	}
	pos := 0
	for _, want := range order {
		i := strings.Index(body[pos:], want)
		if i < 0 {
			t.Fatalf("body lacks %q after position %d:\n%s", want, pos, body)
		}
		pos += i
	}
	if !strings.HasSuffix(strings.TrimSpace(body), RolloutMarker(rollout)) {
		t.Error("rolloutId marker should close the body")
	}
}
