package config

import (
	"os"
	"reflect"
	"strings"
	"testing"
)

func TestAddKeepActionsEditsOneLine(t *testing.T) {
	src, err := os.ReadFile("../../testdata/day1/autopilot.yaml")
	if err != nil {
		t.Fatal(err)
	}
	out, err := AddKeepActions(src, "iamap-demo-quarterly-role", []string{"ssm:GetParametersByPath"})
	if err != nil {
		t.Fatal(err)
	}
	before, after := strings.Split(string(src), "\n"), strings.Split(string(out), "\n")
	if len(before) != len(after) {
		t.Fatalf("line count changed: %d -> %d", len(before), len(after))
	}
	var changed []string
	for i := range before {
		if before[i] != after[i] {
			changed = append(changed, after[i])
		}
	}
	if !reflect.DeepEqual(changed, []string{"    keepActions: [ssm:GetParametersByPath]"}) {
		t.Errorf("changed lines = %q", changed)
	}
	// Idempotent, and merges with what is already there.
	again, err := AddKeepActions(out, "iamap-demo-quarterly-role", []string{"ssm:GetParametersByPath", "ssm:DescribeParameters"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(again), "keepActions: [ssm:DescribeParameters, ssm:GetParametersByPath]") {
		t.Errorf("merged line wrong:\n%s", again)
	}
}

func TestAddKeepActionsStructuredFallback(t *testing.T) {
	src := []byte(watchOK + `roles:
  - name: a
    keepActions:
      - action: ssm:GetParameter
        resource: arn:aws:ssm:us-east-1:123456789012:parameter/x
  - name: b
`)
	out, err := AddKeepActions(src, "a", []string{"ssm:GetParametersByPath"})
	if err != nil {
		t.Fatal(err)
	}
	c, _ := Parse(out)
	r, _ := c.RoleOrError("a")
	if len(r.KeepActions) != 2 || r.KeepActions[0].Resource == "" || r.KeepActions[1].Action != "ssm:GetParametersByPath" {
		t.Errorf("keepActions = %+v", r.KeepActions)
	}
	// A role with no keepActions key at all.
	out, err = AddKeepActions(src, "b", []string{"sns:Publish"})
	if err != nil {
		t.Fatal(err)
	}
	c, _ = Parse(out)
	if r, _ := c.RoleOrError("b"); len(r.KeepActions) != 1 || r.KeepActions[0].Action != "sns:Publish" {
		t.Errorf("role b keepActions = %+v", r.KeepActions)
	}
	if _, err := AddKeepActions(src, "nobody", []string{"sns:Publish"}); err == nil {
		t.Error("unknown role must fail")
	}
}
