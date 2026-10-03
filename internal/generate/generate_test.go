package generate

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/singha105/iam-autopilot/internal/catalog"
	"github.com/singha105/iam-autopilot/internal/config"
	"github.com/singha105/iam-autopilot/internal/observe"
	"github.com/singha105/iam-autopilot/internal/policy"
)

const tinyCatalog = `{"services":{
 "ssm":{"actions":[{"action":"DescribeParameters","resourceTypes":[]},{"action":"GetParameter","resourceTypes":["parameter"]},{"action":"GetParametersByPath","resourceTypes":["parameter"]},{"action":"PutParameter","resourceTypes":["parameter"]}],
        "resourceTypes":[{"name":"parameter","arnFormats":["arn:${Partition}:ssm:${Region}:${Account}:parameter/${ParameterNameWithoutLeadingSlash}"]}]},
 "dynamodb":{"actions":[{"action":"DescribeTable","resourceTypes":["table"]},{"action":"GetItem","resourceTypes":["table"]},{"action":"ListTables","resourceTypes":[]},{"action":"PutItem","resourceTypes":["table"]},{"action":"Scan","resourceTypes":["table"]}],
        "resourceTypes":[{"name":"table","arnFormats":["arn:${Partition}:dynamodb:${Region}:${Account}:table/${TableName}"]}]},
 "sns":{"actions":[{"action":"ListTopics","resourceTypes":[]},{"action":"Publish","resourceTypes":["topic"]}],
        "resourceTypes":[{"name":"topic","arnFormats":["arn:${Partition}:sns:${Region}:${Account}:${TopicName}"]}]},
 "kms":{"actions":[{"action":"Decrypt","resourceTypes":["key"]},{"action":"Encrypt","resourceTypes":["key"]}],
        "resourceTypes":[{"name":"key","arnFormats":["arn:${Partition}:kms:${Region}:${Account}:key/${KeyId}"]}]},
 "logs":{"actions":[{"action":"CreateLogStream","resourceTypes":["log-group"]},{"action":"PutLogEvents","resourceTypes":["log-group"]}],
        "resourceTypes":[{"name":"log-group","arnFormats":["arn:${Partition}:logs:${Region}:${Account}:log-group:${LogGroupName}"]}]},
 "ec2":{"actions":[{"action":"DescribeRegions","resourceTypes":[]},{"action":"RunInstances","resourceTypes":["instance"]}],
        "resourceTypes":[{"name":"instance","arnFormats":["arn:${Partition}:ec2:${Region}:${Account}:instance/${InstanceId}"]}]}
}}`

const (
	role     = "test-role"
	paramARN = "arn:aws:ssm:us-east-1:123456789012:parameter/app/config"
	tableARN = "arn:aws:dynamodb:us-east-1:123456789012:table/app-table"
)

var (
	now    = time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	inside = now.Add(-time.Hour)
	window = observe.Window{Start: now.Add(-24 * time.Hour), End: now}
)

func cat(t *testing.T) *catalog.Catalog {
	t.Helper()
	c, err := catalog.Load([]byte(tinyCatalog))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func doc(t *testing.T, js string) policy.Document {
	t.Helper()
	d, err := policy.Parse([]byte(js))
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func allow(actions ...string) string {
	b, _ := json.Marshal(actions)
	return `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":` + string(b) + `,"Resource":"*"}]}`
}

func cfg(keep ...config.KeepEntry) config.Config {
	return config.Config{
		Roles:            []config.Role{{Name: role, ObservationDays: 1, KeepActions: keep}},
		DataPlaneActions: map[string][]string{"dynamodb": {"GetItem", "PutItem", "Scan"}, "kms": {"Decrypt", "Encrypt"}},
	}
}

// prof builds a profile. accessed lists namespaces with lastAuthenticated in
// the window; tracked maps namespace -> tracked actions.
func prof(calls []observe.ObservedCall, accessed []string, tracked map[string][]string, excluded ...string) observe.Profile {
	p := observe.Profile{RoleName: role, Window: window, ObservedCalls: calls}
	for _, ns := range accessed {
		t := inside
		sa := observe.ServiceAccess{Namespace: ns, LastAuthenticated: &t, TrackedActions: []observe.TrackedAction{}}
		for _, a := range tracked[ns] {
			sa.TrackedActions = append(sa.TrackedActions, observe.TrackedAction{Action: a, LastAccessed: inside})
		}
		p.ServicesAccessed = append(p.ServicesAccessed, sa)
	}
	for _, a := range excluded {
		p.ExcludedCalls = append(p.ExcludedCalls, observe.ExcludedCall{Action: a, Caller: "the Lambda runtime", Count: 1})
	}
	return p
}

func call(action, resource string) observe.ObservedCall {
	return observe.ObservedCall{Action: action, Resource: resource, Count: 1, FirstSeen: inside, LastSeen: inside, ReadOnly: true}
}

// kept returns "action=res1,res2" per kept action, for compact assertions.
func keptMap(r Result) map[string]string {
	m := map[string]string{}
	for _, k := range r.Summary.Kept {
		m[k.Action] = strings.Join(k.Resources, ",")
	}
	return m
}

func ruleOf(r Result, svc string) string {
	for _, s := range r.Summary.Services {
		if s.Service == svc {
			return s.Rule
		}
	}
	return ""
}

func run(t *testing.T, current string, p observe.Profile, c config.Config) Result {
	t.Helper()
	r, err := Generate(doc(t, current), p, c, cat(t))
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	return r
}

func hasWarning(r Result, sub string) bool {
	for _, w := range r.Summary.Warnings {
		if strings.Contains(w, sub) {
			return true
		}
	}
	return false
}

func TestRules(t *testing.T) {
	tests := []struct {
		name     string
		current  string
		profile  observe.Profile
		config   config.Config
		wantKept map[string]string
		check    func(t *testing.T, r Result)
	}{
		{
			name:     "R1 unused service loses every action",
			current:  allow("ssm:*", "sns:*"),
			profile:  prof([]observe.ObservedCall{call("ssm:GetParameter", paramARN)}, []string{"ssm"}, nil),
			config:   cfg(),
			wantKept: map[string]string{"ssm:GetParameter": paramARN},
			check: func(t *testing.T, r Result) {
				if got := ruleOf(r, "sns"); got != "R1 (unused)" {
					t.Errorf("sns rule = %q", got)
				}
			},
		},
		{
			name:     "R1 a service used only by platform calls counts as unused",
			current:  allow("ssm:*", "kms:Decrypt", "logs:*"),
			profile:  prof([]observe.ObservedCall{call("ssm:GetParameter", paramARN)}, []string{"ssm", "kms", "logs"}, map[string][]string{"kms": {"kms:Decrypt"}, "logs": {"logs:CreateLogStream"}}, "kms:Decrypt", "logs:CreateLogStream"),
			config:   cfg(),
			wantKept: map[string]string{"ssm:GetParameter": paramARN},
			check: func(t *testing.T, r Result) {
				for _, svc := range []string{"kms", "logs"} {
					if got := ruleOf(r, svc); got != "R1 (only platform calls, ADR-002)" {
						t.Errorf("%s rule = %q", svc, got)
					}
				}
			},
		},
		{
			name:     "R1 a used service with no identifiable action is left unchanged",
			current:  allow("ssm:*", "sns:*"),
			profile:  prof([]observe.ObservedCall{call("ssm:GetParameter", paramARN)}, []string{"ssm", "sns"}, nil),
			config:   cfg(),
			wantKept: map[string]string{"ssm:GetParameter": paramARN},
			check: func(t *testing.T, r Result) {
				if ruleOf(r, "sns") != "R1 (used, actions unknown: unchanged)" || r.Summary.Services[0].After != 2 || !hasWarning(r, "sns was used") {
					t.Errorf("sns not left unchanged: %+v %v", r.Summary.Services, r.Summary.Warnings)
				}
			},
		},
		{
			name:     "R2 observed actions keep the resources they were seen on",
			current:  allow("ssm:*"),
			profile:  prof([]observe.ObservedCall{call("ssm:GetParameter", paramARN), call("ssm:DescribeParameters", "*")}, []string{"ssm"}, nil),
			config:   cfg(),
			wantKept: map[string]string{"ssm:GetParameter": paramARN, "ssm:DescribeParameters": "*"},
		},
		{
			name:    "R3 tracked actions are kept on *, but never widen an observed action",
			current: allow("ec2:*", "ssm:*"),
			profile: prof([]observe.ObservedCall{call("ssm:GetParameter", paramARN)}, []string{"ec2", "ssm"},
				map[string][]string{"ec2": {"ec2:DescribeRegions"}, "ssm": {"ssm:GetParameter"}}),
			config:   cfg(),
			wantKept: map[string]string{"ec2:DescribeRegions": "*", "ssm:GetParameter": paramARN},
			check: func(t *testing.T, r Result) {
				if got := ruleOf(r, "ec2"); got != "R3" {
					t.Errorf("ec2 rule = %q", got)
				}
			},
		},
		{
			name:     "R4 data-plane actions of a used service are kept, scoped to observed tables",
			current:  allow("dynamodb:DescribeTable", "dynamodb:GetItem", "dynamodb:PutItem"), // grants no Scan
			profile:  prof([]observe.ObservedCall{call("dynamodb:DescribeTable", tableARN)}, []string{"dynamodb"}, nil),
			config:   cfg(),
			wantKept: map[string]string{"dynamodb:DescribeTable": tableARN, "dynamodb:GetItem": tableARN, "dynamodb:PutItem": tableARN},
			check: func(t *testing.T, r Result) {
				if len(r.Summary.KeptUnobservable) != 2 || r.Summary.KeptUnobservable[0].Rule != "R4" {
					t.Errorf("keptUnobservable = %+v", r.Summary.KeptUnobservable)
				}
			},
		},
		{
			name:     "R4 with no observed resource keeps *",
			current:  allow("dynamodb:*"),
			profile:  prof(nil, []string{"dynamodb"}, nil),
			config:   cfg(),
			wantKept: map[string]string{"dynamodb:GetItem": "*", "dynamodb:PutItem": "*", "dynamodb:Scan": "*"},
		},
		{
			name:     "R4 keeps nothing extra for a service seen only through calls on *",
			current:  allow("dynamodb:*"),
			profile:  prof([]observe.ObservedCall{call("dynamodb:ListTables", "*")}, []string{"dynamodb"}, nil),
			config:   cfg(),
			wantKept: map[string]string{"dynamodb:ListTables": "*"},
			check: func(t *testing.T, r Result) {
				if len(r.Summary.KeptUnobservable) != 0 || !hasWarning(r, "R4: dynamodb was used only through calls on") {
					t.Errorf("keptUnobservable = %+v warnings = %v", r.Summary.KeptUnobservable, r.Summary.Warnings)
				}
			},
		},
		{
			name:    "R4 uses the role's dataPlaneActions override",
			current: allow("dynamodb:*"),
			profile: prof([]observe.ObservedCall{call("dynamodb:DescribeTable", tableARN)}, []string{"dynamodb"}, nil),
			config: func() config.Config {
				c := cfg()
				c.Roles[0].DataPlaneActions = map[string][]string{"dynamodb": {"GetItem"}}
				return c
			}(),
			wantKept: map[string]string{"dynamodb:DescribeTable": tableARN, "dynamodb:GetItem": tableARN},
		},
		{
			name:     "R4 does not apply to an unused service",
			current:  allow("ssm:*", "dynamodb:*"),
			profile:  prof([]observe.ObservedCall{call("ssm:GetParameter", paramARN)}, []string{"ssm"}, nil),
			config:   cfg(),
			wantKept: map[string]string{"ssm:GetParameter": paramARN},
		},
		{
			name:    "R5 never scopes to a resource type the action does not support",
			current: allow("dynamodb:*", "ec2:*"),
			profile: prof([]observe.ObservedCall{
				call("dynamodb:ListTables", tableARN), // supports * only
				call("dynamodb:DescribeTable", paramARN),
			}, []string{"dynamodb"}, nil),
			config: config.Config{Roles: []config.Role{{Name: role}}},
			wantKept: map[string]string{
				"dynamodb:ListTables":    "*",
				"dynamodb:DescribeTable": "*", // an SSM ARN is not a table
			},
			check: func(t *testing.T, r Result) {
				if !hasWarning(r, "R5: dynamodb:DescribeTable cannot be scoped") {
					t.Errorf("warnings = %v", r.Summary.Warnings)
				}
			},
		},
		{
			name:    "R6 keep-lists are always kept, with an optional resource",
			current: allow("ssm:*"),
			profile: prof([]observe.ObservedCall{call("ssm:GetParameter", paramARN)}, []string{"ssm"}, nil),
			config: func() config.Config {
				c := cfg(config.KeepEntry{Action: "ssm:GetParametersByPath"})
				c.NeverRemove = []config.KeepEntry{{Action: "ssm:PutParameter", Resource: paramARN}}
				return c
			}(),
			wantKept: map[string]string{"ssm:GetParameter": paramARN, "ssm:GetParametersByPath": "*", "ssm:PutParameter": paramARN},
		},
		{
			name:     "R6 is recorded even when the action was also observed",
			current:  allow("ssm:*"),
			profile:  prof([]observe.ObservedCall{call("ssm:GetParameter", paramARN), call("ssm:GetParametersByPath", paramARN)}, []string{"ssm"}, nil),
			config:   cfg(config.KeepEntry{Action: "ssm:GetParametersByPath", Resource: paramARN}),
			wantKept: map[string]string{"ssm:GetParameter": paramARN, "ssm:GetParametersByPath": paramARN},
			check: func(t *testing.T, r Result) {
				for _, k := range r.Summary.Kept {
					if k.Action == "ssm:GetParametersByPath" && k.Rule != "R2,R5,R6" {
						t.Errorf("rule = %q, want R2,R5,R6", k.Rule)
					}
				}
			},
		},
		{
			name:     "R7 drops actions the current policy does not grant",
			current:  allow("ssm:*"),
			profile:  prof([]observe.ObservedCall{call("ssm:GetParameter", paramARN)}, []string{"ssm", "logs"}, map[string][]string{"logs": {"logs:CreateLogStream"}}),
			config:   cfg(config.KeepEntry{Action: "sns:Publish"}),
			wantKept: map[string]string{"ssm:GetParameter": paramARN},
			check: func(t *testing.T, r Result) {
				for _, w := range []string{"R7: dropped logs:CreateLogStream", "R7: dropped sns:Publish"} {
					if !hasWarning(r, w) {
						t.Errorf("missing warning %q in %v", w, r.Summary.Warnings)
					}
				}
			},
		},
		{
			name:     "R7 narrows a resource the current policy does not cover",
			current:  `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["ssm:GetParameter","ssm:GetParametersByPath"],"Resource":["` + paramARN + `"]}]}`,
			profile:  prof([]observe.ObservedCall{call("ssm:GetParameter", paramARN)}, []string{"ssm"}, nil),
			config:   cfg(config.KeepEntry{Action: "ssm:GetParametersByPath"}), // would be "*"
			wantKept: map[string]string{"ssm:GetParameter": paramARN, "ssm:GetParametersByPath": paramARN},
		},
		{
			name:     "R7 copies Deny statements unchanged",
			current:  `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"ssm:*","Resource":"*"},{"Sid":"NoWrites","Effect":"Deny","Action":"ssm:PutParameter","Resource":"*","Condition":{"Bool":{"aws:SecureTransport":"false"}}}]}`,
			profile:  prof([]observe.ObservedCall{call("ssm:GetParameter", paramARN)}, []string{"ssm"}, nil),
			config:   cfg(),
			wantKept: map[string]string{"ssm:GetParameter": paramARN},
			check: func(t *testing.T, r Result) {
				var deny *policy.Statement
				for i, s := range r.Policy.Statement {
					if s.Effect == "Deny" {
						deny = &r.Policy.Statement[i]
					}
				}
				if deny == nil || deny.Sid != "NoWrites" || !bytes.Contains(deny.Condition, []byte("aws:SecureTransport")) {
					t.Errorf("Deny not copied: %+v", r.Policy.Statement)
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := run(t, tt.current, tt.profile, tt.config)
			if got := keptMap(r); !reflect.DeepEqual(got, tt.wantKept) {
				t.Errorf("kept = %v\nwant %v\nwarnings %v", got, tt.wantKept, r.Summary.Warnings)
			}
			if tt.check != nil {
				tt.check(t, r)
			}
		})
	}
}

func TestStatementGroupingAndCounts(t *testing.T) {
	r := run(t, allow("ssm:*", "dynamodb:*", "sns:*"),
		prof([]observe.ObservedCall{
			call("ssm:GetParameter", paramARN),
			call("ssm:GetParametersByPath", paramARN),
			call("ssm:DescribeParameters", "*"),
			call("dynamodb:DescribeTable", tableARN),
		}, []string{"ssm", "dynamodb"}, nil),
		config.Config{Roles: []config.Role{{Name: role}}})

	var sids []string
	for _, s := range r.Policy.Statement {
		sids = append(sids, fmt.Sprintf("%s:%v@%v", s.Sid, s.Action, s.Resource))
	}
	want := []string{
		"Dynamodb0:[dynamodb:DescribeTable]@[" + tableARN + "]",
		"Ssm0:[ssm:DescribeParameters]@[*]",
		"Ssm1:[ssm:GetParameter ssm:GetParametersByPath]@[" + paramARN + "]",
	}
	if !reflect.DeepEqual(sids, want) {
		t.Errorf("statements =\n%v\nwant\n%v", sids, want)
	}
	s := r.Summary
	// before: ssm 4 + dynamodb 5 + sns 2 = 11; after: 4 actions.
	if s.GrantedBefore != 11 || s.GrantedAfter != 4 || s.RemovedCount != 7 || s.RemovedPercent != 63.6 {
		t.Errorf("counts = %d -> %d, removed %d (%.1f%%)", s.GrantedBefore, s.GrantedAfter, s.RemovedCount, s.RemovedPercent)
	}
	if !bytes.HasSuffix(r.PolicyJSON, []byte("}\n")) || !bytes.Contains(r.PolicyJSON, []byte("\n  \"Statement\"")) {
		t.Errorf("policy JSON not 2-space indented with trailing newline:\n%s", r.PolicyJSON)
	}
}

func TestSizeLimit(t *testing.T) {
	var calls []observe.ObservedCall
	for i := range 120 {
		calls = append(calls, call("ssm:GetParameter", fmt.Sprintf("%s/%03d-a-fairly-long-parameter-name", paramARN, i)))
	}
	_, err := Generate(doc(t, allow("ssm:*")), prof(calls, []string{"ssm"}, nil), cfg(), cat(t))
	if err == nil || !strings.Contains(err.Error(), "even after merging") {
		t.Fatalf("err = %v, want size-limit error", err)
	}
}

func TestMergePerService(t *testing.T) {
	d := policy.Document{Version: policy.Version, Statement: policy.Statements{
		{Sid: "Ssm0", Effect: "Allow", Action: policy.Strings{"ssm:DescribeParameters"}, Resource: policy.Strings{"*"}},
		{Sid: "Ssm1", Effect: "Allow", Action: policy.Strings{"ssm:GetParameter"}, Resource: policy.Strings{paramARN}},
		{Sid: "X", Effect: "Deny", Action: policy.Strings{"ssm:PutParameter"}, Resource: policy.Strings{"*"}},
	}}
	got := mergePerService(d)
	if len(got.Statement) != 2 || got.Statement[0].Sid != "Ssm0" || !reflect.DeepEqual(got.Statement[0].Resource, policy.Strings{"*"}) ||
		len(got.Statement[0].Action) != 2 || got.Statement[1].Effect != "Deny" {
		t.Errorf("merged = %+v", got.Statement)
	}
}

func TestGenerateRefuses(t *testing.T) {
	p := prof(nil, nil, nil)
	for name, js := range map[string]string{
		"NotAction":   `{"Statement":[{"Effect":"Allow","NotAction":"iam:*","Resource":"*"}]}`,
		"NotResource": `{"Statement":[{"Effect":"Allow","Action":"ssm:*","NotResource":"x"}]}`,
		"Condition":   `{"Statement":[{"Effect":"Allow","Action":"ssm:*","Resource":"*","Condition":{"Bool":{"aws:SecureTransport":"true"}}}]}`,
	} {
		if _, err := Generate(doc(t, js), p, cfg(), cat(t)); err == nil {
			t.Errorf("%s: Generate succeeded, want error", name)
		}
	}
	p.RoleName = "not-configured"
	if _, err := Generate(doc(t, allow("ssm:*")), p, cfg(), cat(t)); err == nil || !strings.Contains(err.Error(), "autopilot.yaml") {
		t.Errorf("unconfigured role: err = %v", err)
	}
}

func TestGenerateIsDeterministic(t *testing.T) {
	p := prof([]observe.ObservedCall{
		call("ssm:GetParameter", paramARN), call("dynamodb:DescribeTable", tableARN), call("ssm:DescribeParameters", "*"),
	}, []string{"ssm", "dynamodb", "ec2"}, map[string][]string{"ec2": {"ec2:DescribeRegions"}})
	var outs [][]byte
	for range 5 {
		r := run(t, allow("ssm:*", "dynamodb:*", "ec2:*", "sns:*"), p, cfg(config.KeepEntry{Action: "ssm:GetParametersByPath"}))
		s, _ := json.Marshal(r.Summary)
		outs = append(outs, append(r.PolicyJSON, append([]byte(r.Summary.Markdown()), s...)...))
	}
	for i := 1; i < len(outs); i++ {
		if !bytes.Equal(outs[0], outs[i]) {
			t.Fatalf("run %d differs from run 0", i)
		}
	}
}
