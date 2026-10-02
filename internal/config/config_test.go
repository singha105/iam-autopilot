package config

import (
	"reflect"
	"strings"
	"testing"
)

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
	c, err := Parse([]byte(`
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
	for name, doc := range map[string]string{
		"unknown field (typo)": "roles:\n  - name: r\n    keepActons: [ssm:GetParameter]\n",
		"duplicate role":       "roles:\n  - name: r\n  - name: r\n",
		"bad action name":      "neverRemove: [GetParameter]\n",
		"observation too long": "roles:\n  - name: r\n    observationDays: 120\n",
		"role without name":    "roles:\n  - observationDays: 1\n",
	} {
		if _, err := Parse([]byte(doc)); err == nil {
			t.Errorf("%s: Parse succeeded, want error", name)
		} else if !strings.HasPrefix(err.Error(), "config:") {
			t.Errorf("%s: error %q lacks config: prefix", name, err)
		}
	}
}

func TestDataPlaneFor(t *testing.T) {
	c, err := Parse([]byte(`
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
