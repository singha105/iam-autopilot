package observe

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	"github.com/aws/aws-sdk-go-v2/service/iam"
)

var update = flag.Bool("update", false, "rewrite testdata/observe/*/expected-profile.json from the recorded fixtures")

const fixtureRoot = "../../testdata/observe"

// fixtureMeta mirrors the meta.json the CLI writes with --record.
type fixtureMeta struct {
	RoleName string    `json:"roleName"`
	Days     int       `json:"days"`
	Now      time.Time `json:"now"`
}

// replay serves recorded responses for one operation in call order.
type replay struct {
	t    *testing.T
	dir  string
	next map[string]int
}

func (r *replay) load(op string, v any) error {
	r.next[op]++
	path := filepath.Join(r.dir, fmt.Sprintf("%s-%03d.json", op, r.next[op]))
	b, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("replay: no fixture %s (the code made more %s calls than were recorded): %w", filepath.Base(path), op, err)
	}
	return json.Unmarshal(b, v)
}

// unused reports recorded fixtures the replay never served.
func (r *replay) unused() []string {
	var out []string
	files, _ := filepath.Glob(filepath.Join(r.dir, "*-[0-9][0-9][0-9].json"))
	for _, f := range files {
		base := filepath.Base(f)
		op := base[:len(base)-len("-001.json")]
		var n int
		fmt.Sscanf(base[len(op)+1:], "%03d.json", &n)
		if n > r.next[op] {
			out = append(out, base)
		}
	}
	return out
}

type replayCloudTrail struct{ *replay }

func (r replayCloudTrail) LookupEvents(context.Context, *cloudtrail.LookupEventsInput, ...func(*cloudtrail.Options)) (*cloudtrail.LookupEventsOutput, error) {
	var out cloudtrail.LookupEventsOutput
	return &out, r.load(OpLookupEvents, &out)
}

type replayIAM struct{ *replay }

func (r replayIAM) GetRole(context.Context, *iam.GetRoleInput, ...func(*iam.Options)) (*iam.GetRoleOutput, error) {
	var out iam.GetRoleOutput
	return &out, r.load(OpGetRole, &out)
}

func (r replayIAM) ListRoleTags(context.Context, *iam.ListRoleTagsInput, ...func(*iam.Options)) (*iam.ListRoleTagsOutput, error) {
	var out iam.ListRoleTagsOutput
	return &out, r.load(OpListRoleTags, &out)
}

func (r replayIAM) GenerateServiceLastAccessedDetails(context.Context, *iam.GenerateServiceLastAccessedDetailsInput, ...func(*iam.Options)) (*iam.GenerateServiceLastAccessedDetailsOutput, error) {
	var out iam.GenerateServiceLastAccessedDetailsOutput
	return &out, r.load(OpGenerateServiceLastAccessed, &out)
}

func (r replayIAM) GetServiceLastAccessedDetails(context.Context, *iam.GetServiceLastAccessedDetailsInput, ...func(*iam.Options)) (*iam.GetServiceLastAccessedDetailsOutput, error) {
	var out iam.GetServiceLastAccessedDetailsOutput
	return &out, r.load(OpGetServiceLastAccessedDetail, &out)
}

// profileFromFixtures rebuilds a profile from one recorded directory.
func profileFromFixtures(t *testing.T, dir string) Profile {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, "meta.json"))
	if err != nil {
		t.Fatal(err)
	}
	var meta fixtureMeta
	if err := json.Unmarshal(raw, &meta); err != nil {
		t.Fatal(err)
	}
	r := &replay{t: t, dir: dir, next: map[string]int{}}
	o, _ := testObserver(replayCloudTrail{r}, replayIAM{r})
	o.Now = func() time.Time { return meta.Now }
	p, err := o.BuildProfile(context.Background(), meta.RoleName, meta.Now.Add(-time.Duration(meta.Days)*24*time.Hour), meta.Now)
	if err != nil {
		t.Fatalf("BuildProfile from %s: %v", dir, err)
	}
	if left := r.unused(); len(left) > 0 {
		t.Errorf("fixtures never replayed: %v", left)
	}
	return p
}

func fixtureDirs(t *testing.T) []string {
	t.Helper()
	dirs, err := filepath.Glob(filepath.Join(fixtureRoot, "*", "meta.json"))
	if err != nil || len(dirs) == 0 {
		t.Fatalf("no recorded fixtures under %s", fixtureRoot)
	}
	for i := range dirs {
		dirs[i] = filepath.Dir(dirs[i])
	}
	return dirs
}

// TestGoldenProfiles replays each recorded run and compares the profile JSON
// byte for byte with expected-profile.json. Run with -update to regenerate.
func TestGoldenProfiles(t *testing.T) {
	for _, dir := range fixtureDirs(t) {
		t.Run(filepath.Base(dir), func(t *testing.T) {
			got, err := profileFromFixtures(t, dir).Encode()
			if err != nil {
				t.Fatal(err)
			}
			golden := filepath.Join(dir, "expected-profile.json")
			if *update {
				if err := os.WriteFile(golden, got, 0o644); err != nil {
					t.Fatal(err)
				}
				return
			}
			want, err := os.ReadFile(golden)
			if err != nil {
				t.Fatalf("%v (run go test ./internal/observe -update to create it)", err)
			}
			if !bytes.Equal(got, want) {
				t.Errorf("profile differs from %s (run with -update if the change is intended)\n%s", golden, firstDiff(want, got))
			}
		})
	}
}

// TestDemoRoleExpectations pins the Day 2 acceptance criteria to the recorded
// data: the exact actions each demo role used, and the DynamoDB blind spot.
func TestDemoRoleExpectations(t *testing.T) {
	want := map[string][]string{
		"iamap-demo-inventory-role":     {"ec2:DescribeInstances", "ec2:DescribeRegions", "iam:ListRoles", "lambda:ListFunctions", "s3:ListAllMyBuckets"},
		"iamap-demo-config-reader-role": {"dynamodb:DescribeTable", "ssm:GetParameter"},
		"iamap-demo-quarterly-role":     {"ssm:GetParameter"},
	}
	for role, actions := range want {
		t.Run(role, func(t *testing.T) {
			p := profileFromFixtures(t, filepath.Join(fixtureRoot, role))
			var got []string
			for _, c := range p.ObservedCalls {
				got = append(got, c.Action)
			}
			if !reflect.DeepEqual(got, actions) {
				t.Errorf("observed actions = %v, want %v", got, actions)
			}
			if len(p.DeniedCalls) != 0 {
				t.Errorf("denied calls = %+v, want none", p.DeniedCalls)
			}
			if role == "iamap-demo-config-reader-role" {
				// The blind spot: the app reads and writes its item on every run,
				// event history never shows it, Access Advisor shows dynamodb used.
				for _, c := range p.ObservedCalls {
					if c.Action == "dynamodb:GetItem" || c.Action == "dynamodb:PutItem" {
						t.Errorf("%s in observedCalls: event history should not see data-plane calls", c.Action)
					}
				}
				if !strings.Contains(strings.Join(p.AccessedServices(), ","), "dynamodb") {
					t.Errorf("dynamodb not accessed per Access Advisor: %v", p.AccessedServices())
				}
			}
		})
	}
}

func firstDiff(want, got []byte) string {
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
			return fmt.Sprintf("first difference at line %d:\n  want: %s\n   got: %s", i+1, wl, gl)
		}
	}
	return "(no line difference)"
}
