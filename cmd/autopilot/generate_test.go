package main

import (
	"bytes"
	"context"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/accessanalyzer"
	aatypes "github.com/aws/aws-sdk-go-v2/service/accessanalyzer/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"

	"github.com/singha105/iam-autopilot/internal/observe"
)

const (
	cliRole   = "iamap-demo-quarterly-role"
	cliParam  = "arn:aws:ssm:us-east-1:123456789012:parameter/iamap/demo/quarterly/schedule"
	cliPolicy = "arn:aws:iam::123456789012:policy/iamap/managed/iamap-demo-quarterly-policy"
)

type stubPolicyIAM struct{}

func (stubPolicyIAM) ListAttachedRolePolicies(context.Context, *iam.ListAttachedRolePoliciesInput, ...func(*iam.Options)) (*iam.ListAttachedRolePoliciesOutput, error) {
	return &iam.ListAttachedRolePoliciesOutput{AttachedPolicies: []iamtypes.AttachedPolicy{
		{PolicyArn: aws.String("arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole")},
		{PolicyArn: aws.String(cliPolicy)},
	}}, nil
}

func (stubPolicyIAM) GetPolicy(context.Context, *iam.GetPolicyInput, ...func(*iam.Options)) (*iam.GetPolicyOutput, error) {
	return &iam.GetPolicyOutput{Policy: &iamtypes.Policy{PolicyName: aws.String("iamap-demo-quarterly-policy"), Path: aws.String("/iamap/managed/"), DefaultVersionId: aws.String("v1")}}, nil
}

func (stubPolicyIAM) GetPolicyVersion(context.Context, *iam.GetPolicyVersionInput, ...func(*iam.Options)) (*iam.GetPolicyVersionOutput, error) {
	doc := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["ssm:*","sns:*"],"Resource":"*"}]}`
	return &iam.GetPolicyVersionOutput{PolicyVersion: &iamtypes.PolicyVersion{Document: aws.String(url.QueryEscape(doc))}}, nil
}

type stubAnalyzer struct {
	findings []aatypes.ValidatePolicyFinding
}

func (s stubAnalyzer) ValidatePolicy(context.Context, *accessanalyzer.ValidatePolicyInput, ...func(*accessanalyzer.Options)) (*accessanalyzer.ValidatePolicyOutput, error) {
	return &accessanalyzer.ValidatePolicyOutput{Findings: s.findings}, nil
}

// stubSimulator allows everything except the actions in deny.
type stubSimulator struct{ deny map[string]bool }

func (s stubSimulator) SimulateCustomPolicy(_ context.Context, in *iam.SimulateCustomPolicyInput, _ ...func(*iam.Options)) (*iam.SimulateCustomPolicyOutput, error) {
	out := &iam.SimulateCustomPolicyOutput{}
	for _, a := range in.ActionNames {
		d := iamtypes.PolicyEvaluationDecisionTypeAllowed
		if s.deny[a] {
			d = iamtypes.PolicyEvaluationDecisionTypeImplicitDeny
		}
		out.EvaluationResults = append(out.EvaluationResults, iamtypes.EvaluationResult{EvalActionName: aws.String(a), EvalDecision: d})
	}
	return out, nil
}

// setup writes a config and a profile, and installs stub clients.
func setup(t *testing.T, analyzer stubAnalyzer, sim stubSimulator) (dir, profilePath, configPath string) {
	t.Helper()
	dir = t.TempDir()
	configPath = filepath.Join(dir, "autopilot.yaml")
	if err := os.WriteFile(configPath, []byte("watch: {minutes: 30, lagBufferMinutes: 15, pollSeconds: 300}\nroles:\n  - name: "+cliRole+"\n    policyFile: policies/demo/quarterly.json\n    observationDays: 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 10, 1, 11, 0, 0, 0, time.UTC)
	p := observe.Profile{
		RoleName: cliRole, Window: observe.Window{Start: at.Add(-24 * time.Hour), End: at.Add(time.Hour)},
		ObservedCalls:    []observe.ObservedCall{{Action: "ssm:GetParameter", Resource: cliParam, Count: 3, FirstSeen: at, LastSeen: at, ReadOnly: true}},
		ServicesAccessed: []observe.ServiceAccess{{Namespace: "ssm", LastAuthenticated: &at, TrackedActions: []observe.TrackedAction{}}},
	}
	b, _ := p.Encode()
	profilePath = filepath.Join(dir, "profile.json")
	if err := os.WriteFile(profilePath, b, 0o644); err != nil {
		t.Fatal(err)
	}
	old := loadClients
	t.Cleanup(func() { loadClients = old })
	loadClients = func(context.Context, string) (awsClients, error) {
		return awsClients{PolicyIAM: stubPolicyIAM{}, Analyzer: analyzer, Simulator: sim}, nil
	}
	return dir, profilePath, configPath
}

func TestGenerateThenShadow(t *testing.T) {
	dir, profilePath, configPath := setup(t, stubAnalyzer{}, stubSimulator{})
	out := filepath.Join(dir, "out")
	var stdout, stderr bytes.Buffer
	code := run(context.Background(), []string{"generate", "--role", cliRole, "--profile", profilePath, "--config", configPath, "--out-dir", out}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("generate exit %d: %s", code, stderr.String())
	}
	for _, name := range []string{"proposed-policy.json", "summary.json", "summary.md", "profile.json", "current-policy.json"} {
		if _, err := os.Stat(filepath.Join(out, cliRole, name)); err != nil {
			t.Errorf("missing %s", name)
		}
	}
	proposed, _ := os.ReadFile(filepath.Join(out, cliRole, "proposed-policy.json"))
	if !bytes.Contains(proposed, []byte(cliParam)) || bytes.Contains(proposed, []byte("sns")) {
		t.Errorf("proposal:\n%s", proposed)
	}
	md, _ := os.ReadFile(filepath.Join(out, cliRole, "summary.md"))
	if !strings.Contains(string(md), "| sns | ") || !strings.Contains(stdout.String(), "actions granted") {
		t.Errorf("summary.md:\n%s\nstdout:\n%s", md, stdout.String())
	}

	stdout.Reset()
	code = run(context.Background(), []string{"shadow", "--role", cliRole, "--profile", profilePath, "--config", configPath, "--policy", filepath.Join(out, cliRole, "proposed-policy.json")}, &stdout, &stderr)
	if code != 0 || !strings.Contains(stdout.String(), "tested 1, allowed 1, denied 0") {
		t.Errorf("shadow exit %d:\n%s%s", code, stdout.String(), stderr.String())
	}
}

func TestShadowExitsNonZeroOnDenial(t *testing.T) {
	dir, profilePath, configPath := setup(t, stubAnalyzer{}, stubSimulator{deny: map[string]bool{"ssm:GetParameter": true}})
	policyPath := filepath.Join(dir, "p.json")
	os.WriteFile(policyPath, []byte(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["ssm:GetParameter"],"Resource":["*"]}]}`), 0o644)
	var stdout, stderr bytes.Buffer
	code := run(context.Background(), []string{"shadow", "--role", cliRole, "--profile", profilePath, "--config", configPath, "--policy", policyPath}, &stdout, &stderr)
	if code != 1 {
		t.Errorf("exit = %d, want 1", code)
	}
	if !strings.Contains(stdout.String(), "DENIED  ssm:GetParameter on "+cliParam+" (implicitDeny)") || !strings.Contains(stderr.String(), "1 past call(s) would be denied") {
		t.Errorf("stdout:\n%s\nstderr:\n%s", stdout.String(), stderr.String())
	}
}

func TestGenerateFailsOnSecurityWarning(t *testing.T) {
	_, profilePath, configPath := setup(t, stubAnalyzer{findings: []aatypes.ValidatePolicyFinding{{
		FindingType: aatypes.ValidatePolicyFindingTypeSecurityWarning, IssueCode: aws.String("PASS_ROLE_WITH_STAR_IN_RESOURCE"), FindingDetails: aws.String("details"),
	}}}, stubSimulator{})
	var stdout, stderr bytes.Buffer
	code := run(context.Background(), []string{"generate", "--role", cliRole, "--profile", profilePath, "--config", configPath, "--out-dir", t.TempDir()}, &stdout, &stderr)
	if code != 1 || !strings.Contains(stderr.String(), "failed validation") {
		t.Errorf("exit %d, stderr: %s", code, stderr.String())
	}
}

func TestProfileFlagValidation(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run(context.Background(), []string{"generate", "--role", "r", "--profile", "p.json", "--days", "3"}, &stdout, &stderr); code != 2 || !strings.Contains(stderr.String(), "not both") {
		t.Errorf("exit %d: %s", code, stderr.String())
	}
	stderr.Reset()
	if code := run(context.Background(), []string{"shadow", "--role", "r"}, &stdout, &stderr); code != 2 || !strings.Contains(stderr.String(), "--policy is required") {
		t.Errorf("exit %d: %s", code, stderr.String())
	}
}
