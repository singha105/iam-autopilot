package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	cttypes "github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"

	"github.com/singha105/iam-autopilot/internal/config"
	"github.com/singha105/iam-autopilot/internal/githubpr"
	"github.com/singha105/iam-autopilot/internal/store"
)

const cliRoleARN = "arn:aws:iam::123456789012:role/" + cliRole

var cliNow = time.Date(2026, 10, 2, 6, 0, 0, 0, time.UTC)

// memStore is an in-memory rolloutStore with the real conditional semantics.
type memStore struct{ items map[string]store.Rollout }

func (m *memStore) Create(_ context.Context, r store.Rollout) error {
	if _, ok := m.items[r.RolloutID]; ok {
		return store.ErrExists
	}
	m.items[r.RolloutID] = r
	return nil
}

func (m *memStore) Get(_ context.Context, id string) (store.Rollout, error) {
	r, ok := m.items[id]
	if !ok {
		return r, store.ErrNotFound
	}
	return r, nil
}

func (m *memStore) UpdateStatus(_ context.Context, id string, from, to store.Status) error {
	r, ok := m.items[id]
	if !ok || r.Status != from {
		return store.ErrConflict
	}
	r.Status = to
	m.items[id] = r
	return nil
}

func (m *memStore) SetFields(_ context.Context, id string, f map[string]any) error {
	r := m.items[id]
	for k, v := range f {
		switch k {
		case "prNumber":
			r.PRNumber = v.(int)
		case "prUrl":
			r.PRURL = v.(string)
		case "prBranch":
			r.PRBranch = v.(string)
		case "finishedAt":
			r.FinishedAt = v.(string)
		default:
			return fmt.Errorf("memStore: unhandled field %s", k)
		}
	}
	m.items[id] = r
	return nil
}

func (m *memStore) ActiveForRole(_ context.Context, role string) ([]store.Rollout, error) {
	var out []store.Rollout
	for _, r := range m.items {
		if r.RoleName == role && !r.Status.Final() {
			out = append(out, r)
		}
	}
	return out, nil
}

func (m *memStore) ListAll(context.Context) ([]store.Rollout, error) {
	var out []store.Rollout
	for _, r := range m.items {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].RolloutID < out[j].RolloutID })
	return out, nil
}

type fakePR struct {
	opened  []githubpr.PolicyPR
	closed  []string
	openErr error
}

func (f *fakePR) OpenPolicyPR(_ context.Context, in githubpr.PolicyPR) (githubpr.Result, error) {
	if f.openErr != nil {
		return githubpr.Result{}, f.openErr
	}
	f.opened = append(f.opened, in)
	return githubpr.Result{Number: 12, URL: "https://github.com/singha105/iam-autopilot/pull/12", Branch: "autopilot/" + in.RolloutID}, nil
}

func (f *fakePR) ClosePR(_ context.Context, n int, branch, comment string) error {
	f.closed = append(f.closed, fmt.Sprintf("#%d %s %s", n, branch, comment))
	return nil
}

// observeIAM resolves cliRole and reports ssm as used.
type observeIAM struct{}

func (observeIAM) GetRole(context.Context, *iam.GetRoleInput, ...func(*iam.Options)) (*iam.GetRoleOutput, error) {
	return &iam.GetRoleOutput{Role: &iamtypes.Role{RoleName: aws.String(cliRole), Arn: aws.String(cliRoleARN)}}, nil
}

func (observeIAM) ListRoleTags(context.Context, *iam.ListRoleTagsInput, ...func(*iam.Options)) (*iam.ListRoleTagsOutput, error) {
	return &iam.ListRoleTagsOutput{Tags: []iamtypes.Tag{
		{Key: aws.String("autopilot:managed"), Value: aws.String("true")},
		{Key: aws.String("autopilot:function"), Value: aws.String("iamap-demo-quarterly")},
	}}, nil
}

func (observeIAM) GenerateServiceLastAccessedDetails(context.Context, *iam.GenerateServiceLastAccessedDetailsInput, ...func(*iam.Options)) (*iam.GenerateServiceLastAccessedDetailsOutput, error) {
	return &iam.GenerateServiceLastAccessedDetailsOutput{JobId: aws.String("j")}, nil
}

func (observeIAM) GetServiceLastAccessedDetails(context.Context, *iam.GetServiceLastAccessedDetailsInput, ...func(*iam.Options)) (*iam.GetServiceLastAccessedDetailsOutput, error) {
	used := cliNow.Add(-time.Hour)
	return &iam.GetServiceLastAccessedDetailsOutput{JobStatus: iamtypes.JobStatusTypeCompleted, ServicesLastAccessed: []iamtypes.ServiceLastAccessed{
		{ServiceNamespace: aws.String("ssm"), LastAuthenticated: &used},
		{ServiceNamespace: aws.String("sns")},
	}}, nil
}

type observeCloudTrail struct{}

func (observeCloudTrail) LookupEvents(context.Context, *cloudtrail.LookupEventsInput, ...func(*cloudtrail.Options)) (*cloudtrail.LookupEventsOutput, error) {
	at := cliNow.Add(-time.Hour)
	ev := `{"eventSource":"ssm.amazonaws.com","eventName":"GetParameter","eventTime":"` + at.Format(time.RFC3339) + `","awsRegion":"us-east-1","recipientAccountId":"123456789012","readOnly":true,"requestParameters":{"name":"/iamap/demo/quarterly/schedule"},"userIdentity":{"sessionContext":{"sessionIssuer":{"arn":"` + cliRoleARN + `"}}}}`
	return &cloudtrail.LookupEventsOutput{Events: []cttypes.Event{{EventTime: &at, CloudTrailEvent: aws.String(ev)}}}, nil
}

type world struct {
	store      *memStore
	pr         *fakePR
	configPath string
}

func newWorld(t *testing.T, currentDoc string, sim stubSimulator) *world {
	t.Helper()
	w := &world{store: &memStore{items: map[string]store.Rollout{}}, pr: &fakePR{}}
	w.configPath = filepath.Join(t.TempDir(), "autopilot.yaml")
	cfg := "watch: {minutes: 30, lagBufferMinutes: 15, pollSeconds: 300}\nroles:\n  - name: " + cliRole + "\n    policyFile: policies/demo/quarterly.json\n    observationDays: 1\n"
	if err := os.WriteFile(w.configPath, []byte(cfg), 0o644); err != nil {
		t.Fatal(err)
	}
	oldLoad, oldNow, oldPR := loadClients, now, newPRClient
	t.Cleanup(func() { loadClients, now, newPRClient = oldLoad, oldNow, oldPR })
	now = func() time.Time { return cliNow }
	loadClients = func(context.Context, string) (awsClients, error) {
		return awsClients{
			CloudTrail: observeCloudTrail{}, IAM: observeIAM{}, PolicyIAM: stubPolicyIAM{doc: currentDoc},
			Analyzer: stubAnalyzer{}, Simulator: sim,
			Rollouts: func(string) rolloutStore { return w.store },
		}, nil
	}
	newPRClient = func(context.Context, awsClients, config.GitHub) (prClient, error) { return w.pr, nil }
	return w
}

func (w *world) run(args ...string) (int, string, string) {
	var stdout, stderr bytes.Buffer
	code := run(context.Background(), append(args, "--config", w.configPath), &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}

const rolloutID = cliRole + "-20261002T060000Z"

func TestProposeDryRunWritesNothing(t *testing.T) {
	w := newWorld(t, "", stubSimulator{})
	code, out, errOut := w.run("propose", "--role", cliRole, "--dry-run")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	for _, want := range []string{
		"Rollout " + rolloutID + ": PR_OPEN",
		"--dry-run: nothing written",
		"Branch: autopilot/" + rolloutID,
		"File:   policies/demo/quarterly.json",
		"Title:  autopilot: tighten " + cliRole + ":",
		"1 past call replayed through the IAM policy simulator, 0 would be denied.",
		githubpr.RolloutMarker(rolloutID),
	} {
		if !strings.Contains(out, want) {
			t.Errorf("dry-run output lacks %q:\n%s", want, out)
		}
	}
	if len(w.store.items) != 0 || len(w.pr.opened) != 0 {
		t.Errorf("dry-run wrote: store=%d PRs=%d", len(w.store.items), len(w.pr.opened))
	}
}

func TestProposeOpensPRAndRecordsIt(t *testing.T) {
	w := newWorld(t, "", stubSimulator{})
	code, out, errOut := w.run("propose", "--role", cliRole)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	r := w.store.items[rolloutID]
	if r.Status != store.StatusPROpen || r.PRNumber != 12 || r.PRBranch != "autopilot/"+rolloutID || r.PolicyArn != cliPolicy ||
		r.CurrentVersionID != "v1" || r.RoleArn != cliRoleARN || r.FunctionName != "iamap-demo-quarterly" || r.ProposedPolicy == "" ||
		r.Metrics.ShadowTested != 1 || r.Metrics.ObservedActions != 1 || r.CreatedAt != "2026-10-02T06:00:00Z" {
		t.Errorf("record = %+v", r)
	}
	if len(w.pr.opened) != 1 || w.pr.opened[0].PolicyFile != "policies/demo/quarterly.json" || !strings.Contains(w.pr.opened[0].Body, githubpr.RolloutMarker(rolloutID)) {
		t.Errorf("PR = %+v", w.pr.opened)
	}
	if !strings.Contains(out, "opened https://github.com/singha105/iam-autopilot/pull/12") {
		t.Errorf("output:\n%s", out)
	}

	// A second propose is refused while the first is active.
	code, _, errOut = w.run("propose", "--role", cliRole)
	if code != 1 || !strings.Contains(errOut, "is still PR_OPEN") {
		t.Errorf("second propose: exit %d, %s", code, errOut)
	}
}

func TestProposeShadowFailed(t *testing.T) {
	w := newWorld(t, "", stubSimulator{deny: map[string]bool{"ssm:GetParameter": true}})
	code, out, _ := w.run("propose", "--role", cliRole)
	if code != 1 || !strings.Contains(out, "DENIED  ssm:GetParameter") {
		t.Errorf("exit %d:\n%s", code, out)
	}
	if r := w.store.items[rolloutID]; r.Status != store.StatusShadowFailed || r.FinishedAt == "" || r.Metrics.ShadowDenied != 1 {
		t.Errorf("record = %+v", r)
	}
	if len(w.pr.opened) != 0 {
		t.Error("no PR may be opened when shadow fails")
	}
}

func TestProposeNothingToDo(t *testing.T) {
	minimal := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["ssm:GetParameter"],"Resource":["` + cliParam + `"]}]}`
	w := newWorld(t, minimal, stubSimulator{})
	code, out, errOut := w.run("propose", "--role", cliRole)
	if code != 0 || !strings.Contains(out, "NOTHING_TO_DO") {
		t.Fatalf("exit %d: %s%s", code, out, errOut)
	}
	if r := w.store.items[rolloutID]; r.Status != store.StatusNothingToDo || len(w.pr.opened) != 0 {
		t.Errorf("record = %+v, PRs = %d", r, len(w.pr.opened))
	}
}

func TestProposePRFailureMarksFailed(t *testing.T) {
	w := newWorld(t, "", stubSimulator{})
	w.pr.openErr = errors.New("403 Resource not accessible by personal access token")
	code, _, errOut := w.run("propose", "--role", cliRole)
	if code != 1 || !strings.Contains(errOut, "403") {
		t.Errorf("exit %d: %s", code, errOut)
	}
	if r := w.store.items[rolloutID]; r.Status != store.StatusFailed || r.FinishedAt == "" {
		t.Errorf("record = %+v, want FAILED so it is not left active", r)
	}
}

func TestCancel(t *testing.T) {
	w := newWorld(t, "", stubSimulator{})
	if code, _, errOut := w.run("propose", "--role", cliRole); code != 0 {
		t.Fatal(errOut)
	}
	code, out, errOut := w.run("cancel", "--rollout", rolloutID)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	r := w.store.items[rolloutID]
	if r.Status != store.StatusCancelled || r.FinishedAt == "" {
		t.Errorf("record = %+v", r)
	}
	if len(w.pr.closed) != 1 || !strings.Contains(w.pr.closed[0], "#12 autopilot/"+rolloutID) || !strings.Contains(w.pr.closed[0], githubpr.RolloutMarker(rolloutID)) {
		t.Errorf("closed = %v", w.pr.closed)
	}
	if !strings.Contains(out, "CANCELLED") {
		t.Errorf("output: %s", out)
	}
	// Cancelling again is refused.
	if code, _, errOut := w.run("cancel", "--rollout", rolloutID); code != 1 || !strings.Contains(errOut, "only a PR_OPEN rollout") {
		t.Errorf("second cancel: exit %d, %s", code, errOut)
	}
	// And a new proposal is allowed again.
	now = func() time.Time { return cliNow.Add(time.Minute) }
	if code, _, errOut := w.run("propose", "--role", cliRole, "--dry-run"); code != 0 {
		t.Errorf("propose after cancel: %s", errOut)
	}
}

type stubSSM struct{ value string }

func (s stubSSM) GetParameter(_ context.Context, in *ssm.GetParameterInput, _ ...func(*ssm.Options)) (*ssm.GetParameterOutput, error) {
	if aws.ToString(in.Name) != tokenParameter || !aws.ToBool(in.WithDecryption) {
		return nil, errors.New("wrong parameter request")
	}
	if s.value == "" {
		return nil, errors.New("ParameterNotFound")
	}
	return &ssm.GetParameterOutput{Parameter: &ssmtypes.Parameter{Value: aws.String(s.value)}}, nil
}

func TestGitHubToken(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", "")
	got, err := githubToken(context.Background(), awsClients{SSM: stubSSM{value: "from-ssm"}})
	if err != nil || got != "from-ssm" {
		t.Errorf("SSM token = %q, %v", got, err)
	}
	t.Setenv("GITHUB_TOKEN", "from-env")
	if got, _ := githubToken(context.Background(), awsClients{SSM: stubSSM{value: "from-ssm"}}); got != "from-env" {
		t.Errorf("GITHUB_TOKEN must win, got %q", got)
	}
	t.Setenv("GITHUB_TOKEN", "")
	if _, err := githubToken(context.Background(), awsClients{SSM: stubSSM{}}); !errors.Is(err, githubpr.ErrNoToken) {
		t.Errorf("missing token: err = %v", err)
	}
}

func TestReport(t *testing.T) {
	all := []store.Rollout{
		{RolloutID: "r-2", RoleName: "role-a", Status: store.StatusEnforced, PRNumber: 2, PRURL: "https://github.com/o/r/pull/2",
			PrevVersionID: "v1", NewVersionID: "v2", EnforcedAt: "2026-10-02T10:00:00Z",
			Metrics: store.Metrics{GrantedBefore: 1273, GrantedAfter: 5, RemovedPercent: 99.6, ShadowTested: 5}},
		{RolloutID: "r-1", RoleName: "role-b", Status: store.StatusRolledBack, PRNumber: 3,
			Metrics: store.Metrics{GrantedBefore: 532, GrantedAfter: 1, RemovedPercent: 99.8, DetectSeconds: 64, RollbackSeconds: 2, DeniedActions: []string{"ssm:GetParametersByPath"}}},
		{RolloutID: "r-0", RoleName: "role-a", Status: store.StatusFailed},
	}
	var short bytes.Buffer
	writeReport(&short, all, true)
	lines := strings.Split(strings.TrimSpace(short.String()), "\n")
	if len(lines) != 4 || !strings.Contains(lines[1], "ENFORCED") || !strings.Contains(lines[1], "#2") || !strings.Contains(lines[1], "99.6% (1273 -> 5)") || !strings.Contains(lines[3], "FAILED") {
		t.Errorf("short report:\n%s", short.String())
	}
	var long bytes.Buffer
	writeReport(&long, all, false)
	for _, want := range []string{"versions       v1 -> v2", "timings        detect 64 s, rollback 2 s", "denied         ssm:GetParametersByPath", "shadow         5 replayed, 0 denied"} {
		if !strings.Contains(long.String(), want) {
			t.Errorf("long report lacks %q:\n%s", want, long.String())
		}
	}
}
