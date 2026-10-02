package generate

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/iam"

	"github.com/singha105/iam-autopilot/internal/catalog"
	"github.com/singha105/iam-autopilot/internal/config"
	"github.com/singha105/iam-autopilot/internal/observe"
)

var update = flag.Bool("update", false, "rewrite testdata/generate/*/expected-*.json from the fixtures")

var demoRoles = []string{"iamap-demo-config-reader-role", "iamap-demo-inventory-role", "iamap-demo-quarterly-role"}

// replayPolicyIAM serves the recorded CurrentPolicy responses of one role.
type replayPolicyIAM struct {
	t   *testing.T
	dir string
}

func (r replayPolicyIAM) load(op string, v any) error {
	b, err := os.ReadFile(filepath.Join(r.dir, op+"-001.json"))
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

func (r replayPolicyIAM) ListAttachedRolePolicies(context.Context, *iam.ListAttachedRolePoliciesInput, ...func(*iam.Options)) (*iam.ListAttachedRolePoliciesOutput, error) {
	var out iam.ListAttachedRolePoliciesOutput
	return &out, r.load(OpListAttachedRolePolicies, &out)
}

func (r replayPolicyIAM) GetPolicy(context.Context, *iam.GetPolicyInput, ...func(*iam.Options)) (*iam.GetPolicyOutput, error) {
	var out iam.GetPolicyOutput
	return &out, r.load(OpGetPolicy, &out)
}

func (r replayPolicyIAM) GetPolicyVersion(context.Context, *iam.GetPolicyVersionInput, ...func(*iam.Options)) (*iam.GetPolicyVersionOutput, error) {
	var out iam.GetPolicyVersionOutput
	return &out, r.load(OpGetPolicyVersion, &out)
}

// generateFromFixtures runs the real CurrentPolicy (on recorded responses)
// and Generate (on the Day 2 recorded profile) for one demo role.
func generateFromFixtures(t *testing.T, role string) Result {
	t.Helper()
	current, err := CurrentPolicy(context.Background(), replayPolicyIAM{t, filepath.Join("../../testdata/generate", role)}, role)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join("../../testdata/observe", role, "expected-profile.json"))
	if err != nil {
		t.Fatal(err)
	}
	var prof observe.Profile
	if err := json.Unmarshal(raw, &prof); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load("../../autopilot.yaml")
	if err != nil {
		t.Fatal(err)
	}
	cat, err := catalog.Default()
	if err != nil {
		t.Fatal(err)
	}
	res, err := Generate(current.Document, prof, cfg, cat)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func TestGoldenProposals(t *testing.T) {
	for _, role := range demoRoles {
		t.Run(role, func(t *testing.T) {
			res := generateFromFixtures(t, role)
			summary, _ := json.MarshalIndent(res.Summary, "", "  ")
			files := map[string][]byte{
				"expected-proposed-policy.json": res.PolicyJSON,
				"expected-summary.json":         append(summary, '\n'),
			}
			for name, got := range files {
				path := filepath.Join("../../testdata/generate", role, name)
				if *update {
					if err := os.WriteFile(path, got, 0o644); err != nil {
						t.Fatal(err)
					}
					continue
				}
				want, err := os.ReadFile(path)
				if err != nil {
					t.Fatalf("%v (run go test ./internal/generate -update)", err)
				}
				if !bytes.Equal(got, want) {
					t.Errorf("%s differs (run with -update if intended):\n%s", path, lineDiff(want, got))
				}
			}
		})
	}
}

// TestDemoProposalExpectations pins the Day 3 acceptance criteria.
func TestDemoProposalExpectations(t *testing.T) {
	const acct = "123456789012"
	table := "arn:aws:dynamodb:us-east-1:" + acct + ":table/iamap-demo-config"
	want := map[string]map[string]string{
		"iamap-demo-inventory-role": {
			"ec2:DescribeInstances": "*", "ec2:DescribeRegions": "*", "iam:ListRoles": "*",
			"lambda:ListFunctions": "*", "s3:ListAllMyBuckets": "*",
		},
		"iamap-demo-config-reader-role": {
			"ssm:GetParameter":       "arn:aws:ssm:us-east-1:" + acct + ":parameter/iamap/demo/config",
			"dynamodb:DescribeTable": table, "dynamodb:GetItem": table, "dynamodb:PutItem": table,
		},
		"iamap-demo-quarterly-role": {
			"ssm:GetParameter": "arn:aws:ssm:us-east-1:" + acct + ":parameter/iamap/demo/quarterly/schedule",
		},
	}
	for role, kept := range want {
		t.Run(role, func(t *testing.T) {
			res := generateFromFixtures(t, role)
			got := map[string]string{}
			for _, k := range res.Summary.Kept {
				got[k.Action] = strings.Join(k.Resources, ",")
			}
			if !reflect.DeepEqual(got, kept) {
				t.Errorf("kept = %v\nwant %v", got, kept)
			}
			var unobservable []string
			for _, k := range res.Summary.KeptUnobservable {
				unobservable = append(unobservable, k.Action)
			}
			sort.Strings(unobservable)
			if role == "iamap-demo-config-reader-role" {
				if !reflect.DeepEqual(unobservable, []string{"dynamodb:GetItem", "dynamodb:PutItem"}) {
					t.Errorf("kept-unobservable = %v", unobservable)
				}
			} else if len(unobservable) != 0 {
				t.Errorf("kept-unobservable = %v, want none", unobservable)
			}
			for _, s := range res.Summary.Services {
				if s.After == 0 && !strings.HasPrefix(s.Rule, RuleUnused) {
					t.Errorf("%s removed but rule is %q", s.Service, s.Rule)
				}
			}
			if res.Summary.RemovedPercent < 95 {
				t.Errorf("removed only %.1f%%", res.Summary.RemovedPercent)
			}
		})
	}
}

func lineDiff(want, got []byte) string {
	w, g := strings.Split(string(want), "\n"), strings.Split(string(got), "\n")
	for i := 0; i < len(w) || i < len(g); i++ {
		var wl, gl string
		if i < len(w) {
			wl = w[i]
		}
		if i < len(g) {
			gl = g[i]
		}
		if wl != gl {
			return fmt.Sprintf("line %d:\n  want: %s\n   got: %s", i+1, wl, gl)
		}
	}
	return ""
}
