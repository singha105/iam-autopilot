package config

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
)

const watchOK = "watch: {minutes: 30, lagBufferMinutes: 15, pollSeconds: 300}\n"

func TestLoadRepoConfig(t *testing.T) {
	c, err := Load("../../autopilot.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Roles) != 3 {
		t.Fatalf("roles = %d, want 3", len(c.Roles))
	}
	r, ok := c.Role("iamap-demo-config-reader-role")
	if !ok || r.ObservationDays != 1 {
		t.Errorf("config-reader role = %+v, %v", r, ok)
	}
	want := []string{"dynamodb:BatchGetItem", "dynamodb:BatchWriteItem", "dynamodb:DeleteItem", "dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:Query", "dynamodb:Scan", "dynamodb:UpdateItem"}
	if got := c.DataPlane("dynamodb"); !reflect.DeepEqual(got, want) {
		t.Errorf("DataPlane(dynamodb) = %v", got)
	}
	if c.Watch.Minutes != 30 || c.Watch.PollSeconds != 300 {
		t.Errorf("watch = %+v", c.Watch)
	}
}

func TestKeepEntryForms(t *testing.T) {
	c, err := Parse([]byte(watchOK + `
roles:
  - name: r
    observationDays: 7
    keepActions:
      - ssm:GetParametersByPath
      - action: ssm:GetParameter
        resource: arn:aws:ssm:us-east-1:123456789012:parameter/x
neverRemove: [sts:GetCallerIdentity]
`))
	if err != nil {
		t.Fatal(err)
	}
	r, _ := c.Role("r")
	want := []KeepEntry{{Action: "ssm:GetParametersByPath"}, {Action: "ssm:GetParameter", Resource: "arn:aws:ssm:us-east-1:123456789012:parameter/x"}}
	if !reflect.DeepEqual(r.KeepActions, want) {
		t.Errorf("keepActions = %+v", r.KeepActions)
	}
	if r.KeepActions[0].ResourceOrStar() != "*" || c.NeverRemove[0].Action != "sts:GetCallerIdentity" {
		t.Errorf("defaults wrong: %+v %+v", r.KeepActions[0], c.NeverRemove)
	}
}

func TestParseRejects(t *testing.T) {
	// Each case has a valid watch block, so it fails for its own reason.
	for name, doc := range map[string]string{
		"unknown field (typo)":        watchOK + "roles:\n  - name: r\n    keepActons: [ssm:GetParameter]\n",
		"duplicate role":              watchOK + "roles:\n  - name: r\n  - name: r\n",
		"bad action name":             watchOK + "neverRemove: [GetParameter]\n",
		"observation too long":        watchOK + "roles:\n  - name: r\n    observationDays: 120\n",
		"role without name":           watchOK + "roles:\n  - observationDays: 1\n",
		"policyFile outside policies": watchOK + "roles:\n  - name: r\n    policyFile: ../secrets.json\n",
		"policyFile not json":         watchOK + "roles:\n  - name: r\n    policyFile: policies/demo/x.yaml\n",
		"missing watch":               "roles:\n  - name: r\n",
		"watch minutes zero":          "watch: {minutes: 0, lagBufferMinutes: 15, pollSeconds: 300}\nroles:\n  - name: r\n",
		"watch poll negative":         "watch: {minutes: 30, lagBufferMinutes: 15, pollSeconds: -1}\nroles:\n  - name: r\n",
	} {
		if _, err := Parse([]byte(doc)); err == nil {
			t.Errorf("%s: Parse succeeded, want error", name)
		} else if !strings.HasPrefix(err.Error(), "config:") {
			t.Errorf("%s: error %q lacks config: prefix", name, err)
		}
	}
}

func TestDefaultsAndRoleLookup(t *testing.T) {
	c, err := Parse([]byte(watchOK + "roles:\n  - name: r\n    policyFile: policies/demo/r.json\n"))
	if err != nil {
		t.Fatal(err)
	}
	if c.GitHub != (GitHub{Owner: "singha105", Repo: "iam-autopilot", Branch: "main"}) {
		t.Errorf("github defaults = %+v", c.GitHub)
	}
	if r, err := c.RoleOrError("r"); err != nil || r.PolicyFile != "policies/demo/r.json" {
		t.Errorf("RoleOrError(r) = %+v, %v", r, err)
	}
	if _, err := c.RoleOrError("someone-else"); err == nil || !strings.Contains(err.Error(), "not listed in autopilot.yaml") {
		t.Errorf("unknown role: err = %v", err)
	}
}

type fakeFetcher struct {
	files map[string]string
	got   []string
}

func (f *fakeFetcher) FetchFile(_ context.Context, path, ref string) ([]byte, error) {
	f.got = append(f.got, path+"@"+ref)
	b, ok := f.files[path]
	if !ok {
		return nil, errors.New("404 Not Found")
	}
	return []byte(b), nil
}

func TestLoadFromGitHubUsesTheSameValidation(t *testing.T) {
	f := &fakeFetcher{files: map[string]string{"autopilot.yaml": watchOK + "roles:\n  - name: r\n"}}
	c, err := LoadFrom(context.Background(), f, "autopilot.yaml", "main")
	if err != nil || len(c.Roles) != 1 || !reflect.DeepEqual(f.got, []string{"autopilot.yaml@main"}) {
		t.Fatalf("LoadFrom = %+v, %v (fetched %v)", c, err, f.got)
	}
	f.files["autopilot.yaml"] = "roles:\n  - name: r\n" // no watch block
	if _, err := LoadFrom(context.Background(), f, "autopilot.yaml", "main"); err == nil {
		t.Error("LoadFrom must validate like Load")
	}
	if _, err := LoadFrom(context.Background(), f, "missing.yaml", "main"); err == nil || !strings.Contains(err.Error(), "missing.yaml@main") {
		t.Errorf("fetch error: %v", err)
	}
}

func TestDataPlaneFor(t *testing.T) {
	c, err := Parse([]byte(watchOK + `
roles:
  - name: narrow
    dataPlaneActions:
      dynamodb: [PutItem, GetItem]
      s3: []
  - name: default
dataPlaneActions:
  dynamodb: [GetItem, PutItem, Scan]
  s3: [GetObject]
`))
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		role, svc string
		want      []string
	}{
		{"narrow", "dynamodb", []string{"dynamodb:GetItem", "dynamodb:PutItem"}},
		{"narrow", "s3", []string{}}, // explicitly none
		{"default", "dynamodb", []string{"dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:Scan"}},
		{"unknown", "s3", []string{"s3:GetObject"}},
	} {
		if got := c.DataPlaneFor(tt.role, tt.svc); !reflect.DeepEqual(got, tt.want) {
			t.Errorf("DataPlaneFor(%s, %s) = %v, want %v", tt.role, tt.svc, got, tt.want)
		}
	}
}
