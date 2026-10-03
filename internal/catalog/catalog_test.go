package catalog

import (
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/singha105/iam-autopilot/internal/policy"
)

// A tiny catalog keeps most tests independent of the real data file.
const tiny = `{"services":{
  "iam":{"actions":[{"action":"GetRole","resourceTypes":["role"]},{"action":"GetUser","resourceTypes":["user"]},{"action":"ListRoles","resourceTypes":[]},{"action":"PassRole","resourceTypes":["role"]}],
         "resourceTypes":[{"name":"role","arnFormats":["arn:${Partition}:iam::${Account}:role/${RoleNameWithPath}"]},{"name":"user","arnFormats":["arn:${Partition}:iam::${Account}:user/${UserNameWithPath}"]}]},
  "ssm":{"actions":[{"action":"GetParameter","resourceTypes":["parameter"]},{"action":"GetParameters","resourceTypes":["parameter"]},{"action":"DescribeParameters","resourceTypes":[]}],
         "resourceTypes":[{"name":"parameter","arnFormats":["arn:${Partition}:ssm:${Region}:${Account}:parameter/${ParameterNameWithoutLeadingSlash}"]}]}
}}`

func tinyCatalog(t *testing.T) *Catalog {
	t.Helper()
	c, err := Load([]byte(tiny))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestExpand(t *testing.T) {
	c := tinyCatalog(t)
	tests := map[string][]string{
		"*":                 {"iam:GetRole", "iam:GetUser", "iam:ListRoles", "iam:PassRole", "ssm:DescribeParameters", "ssm:GetParameter", "ssm:GetParameters"},
		"iam:*":             {"iam:GetRole", "iam:GetUser", "iam:ListRoles", "iam:PassRole"},
		"iam:Get*":          {"iam:GetRole", "iam:GetUser"},
		"IAM:get*":          {"iam:GetRole", "iam:GetUser"}, // case-insensitive
		"ssm:GetParameter":  {"ssm:GetParameter"},           // exact, not a prefix
		"ssm:getparameter":  {"ssm:GetParameter"},           // canonical case returned
		"ssm:GetParameter?": {"ssm:GetParameters"},          // ? is one character
		"*:List*":           {"iam:ListRoles"},
		"sqs:*":             nil, // service not in this catalog
		"iam:Nope":          nil,
	}
	for pattern, want := range tests {
		if got := c.Expand(pattern); !reflect.DeepEqual(got, want) {
			t.Errorf("Expand(%q) = %v, want %v", pattern, got, want)
		}
	}
}

func TestMatches(t *testing.T) {
	tests := []struct {
		pattern, action string
		want            bool
	}{
		{"ssm:*", "ssm:GetParameter", true},
		{"ssm:Get*", "ssm:GetParametersByPath", true},
		{"SSM:GET*", "ssm:GetParameter", true},
		{"ssm:GetParameter", "ssm:GetParametersByPath", false},
		{"ssm:GetParameter?", "ssm:GetParameters", true},
		{"*", "anything:AtAll", true},
		{"s3:*", "s3control:ListJobs", false},
		{"ec2:Describe*", "ec2:DescribeRegions", true},
		{"ec2:Describe*", "ec2:RunInstances", false},
	}
	for _, tt := range tests {
		if got := Matches(tt.pattern, tt.action); got != tt.want {
			t.Errorf("Matches(%q, %q) = %v, want %v", tt.pattern, tt.action, got, tt.want)
		}
	}
}

func TestActionFacts(t *testing.T) {
	c := tinyCatalog(t)
	if !c.Exists("iam:getrole") || c.Exists("iam:DeleteRole") {
		t.Error("Exists is wrong")
	}
	if !c.SupportsResources("ssm:GetParameter") || c.SupportsResources("iam:ListRoles") || c.SupportsResources("iam:Unknown") {
		t.Error("SupportsResources is wrong")
	}
	if c.Canonical("SSM:getparameter") != "ssm:GetParameter" {
		t.Errorf("Canonical = %q", c.Canonical("SSM:getparameter"))
	}
}

func TestARNFitsAction(t *testing.T) {
	c := tinyCatalog(t)
	tests := []struct {
		action, arn string
		want        bool
	}{
		{"ssm:GetParameter", "arn:aws:ssm:us-east-1:123456789012:parameter/iamap/demo/config", true},
		{"ssm:GetParameter", "arn:aws:dynamodb:us-east-1:123456789012:table/t", false},
		{"iam:GetRole", "arn:aws:iam::123456789012:role/iamap/x", true},
		{"iam:GetRole", "arn:aws:iam::123456789012:user/bob", false},
		{"iam:ListRoles", "arn:aws:iam::123456789012:role/r", false}, // supports "*" only
		{"iam:Unknown", "*", false},
	}
	for _, tt := range tests {
		if got := c.ARNFitsAction(tt.action, tt.arn); got != tt.want {
			t.Errorf("ARNFitsAction(%q, %q) = %v, want %v", tt.action, tt.arn, got, tt.want)
		}
	}
}

func TestCountGranted(t *testing.T) {
	c := tinyCatalog(t)
	doc := policy.Document{Version: policy.Version, Statement: policy.Statements{
		{Effect: "Allow", Action: policy.Strings{"iam:Get*", "iam:GetRole"}, Resource: policy.Strings{"*"}},
		{Effect: "Allow", Action: policy.Strings{"ssm:GetParameter"}, Resource: policy.Strings{"arn:aws:ssm:us-east-1:123456789012:parameter/x"}},
		{Effect: "Deny", Action: policy.Strings{"*"}, Resource: policy.Strings{"*"}}, // ignored for the count
	}}
	n, err := c.CountGranted(doc)
	if err != nil || n != 3 {
		t.Errorf("CountGranted = %d, %v; want 3 (GetRole, GetUser, GetParameter, duplicates once)", n, err)
	}
}

func TestNotActionIsUnsupported(t *testing.T) {
	c := tinyCatalog(t)
	doc := policy.Document{Statement: policy.Statements{{Sid: "Weird", Effect: "Allow", NotAction: policy.Strings{"iam:*"}, Resource: policy.Strings{"*"}}}}
	if _, err := c.CountGranted(doc); !errors.Is(err, ErrNotAction) {
		t.Errorf("err = %v, want ErrNotAction", err)
	}
	// NotAction in a Deny does not affect the count and is not an error.
	doc.Statement[0].Effect = "Deny"
	if n, err := c.CountGranted(doc); err != nil || n != 0 {
		t.Errorf("Deny NotAction: n=%d err=%v", n, err)
	}
}

// Tests against the real embedded catalog.

func TestEmbeddedCatalog(t *testing.T) {
	c, err := Default()
	if err != nil {
		t.Fatal(err)
	}
	if got := len(c.Expand("*")); got != c.Size() || got < 1500 {
		t.Errorf(`Expand("*") = %d actions, catalog size %d`, got, c.Size())
	}
	for _, a := range []string{"ec2:DescribeRegions", "ec2:DescribeInstances", "s3:ListAllMyBuckets", "lambda:ListFunctions", "iam:ListRoles", "ssm:GetParameter", "ssm:GetParametersByPath", "dynamodb:DescribeTable", "dynamodb:GetItem", "dynamodb:PutItem", "kms:Decrypt"} {
		if !c.Exists(a) {
			t.Errorf("%s missing from the catalog", a)
		}
	}
	for a, want := range map[string]bool{"ssm:GetParameter": true, "dynamodb:GetItem": true, "ec2:DescribeRegions": false, "s3:ListAllMyBuckets": false, "iam:ListRoles": false} {
		if got := c.SupportsResources(a); got != want {
			t.Errorf("SupportsResources(%s) = %v, want %v", a, got, want)
		}
	}
	if !c.ARNFitsAction("dynamodb:GetItem", "arn:aws:dynamodb:us-east-1:123456789012:table/iamap-demo-config") {
		t.Error("table ARN should fit dynamodb:GetItem")
	}
	for _, name := range []string{"inventory", "config-reader", "quarterly"} {
		raw, err := os.ReadFile("../../testdata/day1/" + name + ".json")
		if err != nil {
			t.Fatal(err)
		}
		doc, err := policy.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		granted, err := c.Granted(doc)
		if err != nil || len(granted) < 100 {
			t.Errorf("%s (Day 1 version) grants %d actions (err %v); the original demo policies are deliberately broad", name, len(granted), err)
		}
		for _, a := range granted {
			if strings.HasPrefix(a, "iam:") && !strings.HasPrefix(a, "iam:Get") && !strings.HasPrefix(a, "iam:List") {
				t.Errorf("%s: iam:Get*/List* expanded to %s", name, a)
			}
		}
	}
}
