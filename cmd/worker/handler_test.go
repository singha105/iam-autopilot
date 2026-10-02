package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sfn"

	"github.com/singha105/iam-autopilot/internal/config"
	"github.com/singha105/iam-autopilot/internal/generate"
	"github.com/singha105/iam-autopilot/internal/githubpr"
	"github.com/singha105/iam-autopilot/internal/observe"
	"github.com/singha105/iam-autopilot/internal/rollout"
	"github.com/singha105/iam-autopilot/internal/shadow"
	"github.com/singha105/iam-autopilot/internal/store"
)

const role = "iamap-demo-inventory-role"

var t0 = time.Date(2026, 10, 2, 8, 0, 0, 0, time.UTC)

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
	r := m.items[id]
	if r.Status != from {
		return store.ErrConflict
	}
	r.Status = to
	m.items[id] = r
	return nil
}

func (m *memStore) SetFields(_ context.Context, id string, f map[string]any) error {
	b, _ := json.Marshal(m.items[id])
	var asMap map[string]any
	json.Unmarshal(b, &asMap)
	for k, v := range f {
		asMap[k] = v
	}
	b, _ = json.Marshal(asMap)
	var out store.Rollout
	if err := json.Unmarshal(b, &out); err != nil {
		return err
	}
	m.items[id] = out
	return nil
}

func (m *memStore) ActiveForRole(_ context.Context, r string) ([]store.Rollout, error) {
	var out []store.Rollout
	for _, x := range m.items {
		if x.RoleName == r && !x.Status.Final() {
			out = append(out, x)
		}
	}
	return out, nil
}

type fakeGitHub struct {
	opened   []githubpr.PolicyPR
	merged   githubpr.MergeInfo
	comments []string
}

func (f *fakeGitHub) OpenPolicyPR(_ context.Context, in githubpr.PolicyPR) (githubpr.Result, error) {
	f.opened = append(f.opened, in)
	return githubpr.Result{Number: 3, URL: "https://github.com/singha105/iam-autopilot/pull/3", Branch: "autopilot/" + in.RolloutID}, nil
}
func (f *fakeGitHub) CommentOnPR(_ context.Context, _ int, md string) error {
	f.comments = append(f.comments, md)
	return nil
}
func (f *fakeGitHub) ClosePR(context.Context, int, string, string) error { return nil }
func (f *fakeGitHub) OpenRevertPR(context.Context, githubpr.RevertPR) (githubpr.Result, error) {
	return githubpr.Result{}, nil
}
func (f *fakeGitHub) IsMerged(context.Context, int) (githubpr.MergeInfo, error) { return f.merged, nil }

type fakeEngine struct {
	calls []string
	watch rollout.WatchResult
}

func (f *fakeEngine) Enforce(_ context.Context, id string) (rollout.EnforceResult, error) {
	f.calls = append(f.calls, "enforce "+id)
	return rollout.EnforceResult{PrevVersionID: "v1", NewVersionID: "v2"}, nil
}
func (f *fakeEngine) Watch(_ context.Context, id string, it int) (rollout.WatchResult, error) {
	f.calls = append(f.calls, "watch "+id)
	w := f.watch
	w.Iteration = it + 1
	return w, nil
}
func (f *fakeEngine) Rollback(_ context.Context, id string, denied []string) (rollout.RollbackResult, error) {
	f.calls = append(f.calls, "rollback "+id+" "+strings.Join(denied, ","))
	return rollout.RollbackResult{}, nil
}
func (f *fakeEngine) Complete(_ context.Context, id string) error {
	f.calls = append(f.calls, "complete "+id)
	return nil
}
func (f *fakeEngine) Cancel(_ context.Context, id, reason string) error {
	f.calls = append(f.calls, "cancel "+id+": "+reason)
	return nil
}
func (f *fakeEngine) MarkFailed(_ context.Context, id, cause string) error {
	f.calls = append(f.calls, "fail "+id+": "+cause)
	return nil
}

type fakeStates struct{ success, failure int }

func (f *fakeStates) SendTaskSuccess(context.Context, *sfn.SendTaskSuccessInput, ...func(*sfn.Options)) (*sfn.SendTaskSuccessOutput, error) {
	f.success++
	return &sfn.SendTaskSuccessOutput{}, nil
}
func (f *fakeStates) SendTaskFailure(context.Context, *sfn.SendTaskFailureInput, ...func(*sfn.Options)) (*sfn.SendTaskFailureOutput, error) {
	f.failure++
	return &sfn.SendTaskFailureOutput{}, nil
}

type world struct {
	d      *deps
	store  *memStore
	gh     *fakeGitHub
	engine *fakeEngine
	states *fakeStates
	plan   rollout.Plan
}

func newWorld(mode string) *world {
	w := &world{store: &memStore{items: map[string]store.Rollout{}}, gh: &fakeGitHub{}, engine: &fakeEngine{}, states: &fakeStates{}}
	summary, _ := json.Marshal(generate.Summary{Role: role, GrantedBefore: 1273, GrantedAfter: 5, RemovedCount: 1268, RemovedPercent: 99.6})
	report, _ := json.Marshal(shadow.Report{Tested: 5, Allowed: 5})
	w.plan = rollout.Plan{Rollout: store.Rollout{
		RoleArn: "arn:aws:iam::123456789012:role/" + role, FunctionName: "iamap-demo-inventory",
		PolicyArn: "arn:aws:iam::123456789012:policy/iamap/managed/iamap-demo-inventory-policy", CurrentVersionID: "v1",
		ProposedPolicy: `{"Version":"2012-10-17","Statement":[]}`, Summary: string(summary), ShadowReport: string(report),
		Status: store.StatusPROpen, Metrics: store.Metrics{GrantedBefore: 1273, GrantedAfter: 5, ShadowTested: 5, DeniedActions: []string{}},
	}}
	cfg := config.Config{
		GitHub: config.GitHub{Owner: "singha105", Repo: "iam-autopilot", Branch: "main"},
		Roles:  []config.Role{{Name: role, PolicyFile: "policies/demo/inventory.json", ObservationDays: 1}},
		Watch:  config.Watch{Minutes: 30, LagBufferMinutes: 15, PollSeconds: 300},
	}
	w.d = &deps{
		mode: mode, now: func() time.Time { return t0 }, log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		store:      w.store,
		loadConfig: func(context.Context) (config.Config, error) { return cfg, nil },
		github:     func(context.Context) (githubClient, error) { return w.gh, nil },
		resolve: func(_ context.Context, r string) (observe.Role, error) {
			if r != role {
				return observe.Role{}, observe.ErrNotManaged
			}
			return observe.Role{Name: role, ARN: w.plan.Rollout.RoleArn, FunctionName: "iamap-demo-inventory"}, nil
		},
		plan: func(_ context.Context, _ config.Config, r, id string) (rollout.Plan, error) {
			p := w.plan
			p.Rollout.RolloutID, p.Rollout.RoleName = id, r
			return p, nil
		},
		engine: func(config.Config, githubClient) engineSteps { return w.engine },
		states: w.states,
	}
	return w
}

func (w *world) step(t *testing.T, raw string) State {
	t.Helper()
	in, err := decode(json.RawMessage(raw))
	if err != nil {
		t.Fatal(err)
	}
	out, err := w.d.handle(context.Background(), in)
	if err != nil {
		t.Fatalf("%s: %v", raw, err)
	}
	return out.(State)
}

const id = role + "-20261002T080000Z"

func TestHappyPathThroughTheSteps(t *testing.T) {
	w := newWorld(ModeWorker)
	s := w.step(t, `{"step":"start","roleName":"`+role+`"}`)
	if s.RolloutID != id || s.PollSeconds != 300 || w.store.items[id].Status != store.StatusObserving {
		t.Fatalf("start: %+v, record %+v", s, w.store.items[id])
	}

	b, _ := json.Marshal(Input{Step: "observe_generate_shadow", State: &s})
	s = w.step(t, string(b))
	r := w.store.items[id]
	if s.ShadowDenied != 0 || s.NothingToDo || r.Status != store.StatusObserving || r.PolicyArn == "" || r.ProposedPolicy == "" || r.Metrics.GrantedAfter != 5 {
		t.Fatalf("observe: %+v, record %+v", s, r)
	}

	b, _ = json.Marshal(Input{Step: "propose", State: &s})
	s = w.step(t, string(b))
	r = w.store.items[id]
	if s.PRNumber != 3 || r.Status != store.StatusPROpen || r.PRBranch != "autopilot/"+id || len(w.gh.opened) != 1 ||
		w.gh.opened[0].PolicyFile != "policies/demo/inventory.json" || !strings.Contains(w.gh.opened[0].Body, githubpr.RolloutMarker(id)) {
		t.Fatalf("propose: %+v, record %+v", s, r)
	}
	// A retried propose does not open a second PR.
	w.step(t, string(b))
	if len(w.gh.opened) != 1 {
		t.Errorf("retried propose opened %d PRs", len(w.gh.opened))
	}

	b, _ = json.Marshal(Input{Step: "await", State: &s, TaskToken: "tok-123"})
	w.step(t, string(b))
	if w.store.items[id].TaskToken != "tok-123" {
		t.Errorf("task token not stored")
	}

	for _, stepName := range []string{"enforce", "watch", "watch", "complete"} {
		b, _ = json.Marshal(Input{Step: stepName, State: &s})
		s = w.step(t, string(b))
	}
	if !reflect.DeepEqual(w.engine.calls, []string{"enforce " + id, "watch " + id, "watch " + id, "complete " + id}) || s.Iteration != 2 {
		t.Errorf("engine calls %v, iteration %d", w.engine.calls, s.Iteration)
	}
}

func TestStartRefuses(t *testing.T) {
	w := newWorld(ModeWorker)
	if _, err := w.d.handle(context.Background(), Input{Step: "start", RoleName: "not-configured"}); err == nil {
		t.Error("a role missing from autopilot.yaml must be refused")
	}
	w.store.items["old"] = store.Rollout{RolloutID: "old", RoleName: role, Status: store.StatusEnforcedWatching}
	_, err := w.d.handle(context.Background(), Input{Step: "start", RoleName: role})
	if err == nil || !strings.Contains(err.Error(), "still ENFORCED_WATCHING") {
		t.Errorf("active rollout: err = %v", err)
	}
}

func TestObserveOutcomes(t *testing.T) {
	for _, tt := range []struct {
		status       store.Status
		denied       int
		wantDenied   int
		wantNothing  bool
		wantErr      bool
		validationOK bool
	}{
		{store.StatusShadowFailed, 2, 2, false, false, true},
		{store.StatusNothingToDo, 0, 0, true, false, true},
		{store.StatusFailed, 0, 0, false, true, false},
	} {
		w := newWorld(ModeWorker)
		w.plan.Rollout.Status = tt.status
		w.plan.Rollout.Metrics.ShadowDenied = tt.denied
		if !tt.validationOK {
			w.plan.ValidationErr = errors.New("proposed policy failed validation: SECURITY_WARNING")
		}
		s := w.step(t, `{"step":"start","roleName":"`+role+`"}`)
		b, _ := json.Marshal(Input{Step: "observe_generate_shadow", State: &s})
		in, _ := decode(b)
		out, err := w.d.handle(context.Background(), in)
		if (err != nil) != tt.wantErr {
			t.Fatalf("%s: err = %v", tt.status, err)
		}
		if tt.wantErr {
			continue
		}
		got := out.(State)
		if got.ShadowDenied != tt.wantDenied || got.NothingToDo != tt.wantNothing || w.store.items[id].Status != tt.status {
			t.Errorf("%s: state %+v, record status %s", tt.status, got, w.store.items[id].Status)
		}
	}
}

func TestRollbackCancelAndFailPassTheirInputs(t *testing.T) {
	w := newWorld(ModeWorker)
	w.step(t, `{"step":"rollback","state":{"rolloutId":"`+id+`","roleName":"`+role+`","deniedActions":["ssm:GetParametersByPath"]}}`)
	w.step(t, `{"step":"cancel","state":{"rolloutId":"`+id+`","roleName":"`+role+`","error":{"Error":"PRClosed","Cause":"PR #3 was closed"}}}`)
	w.step(t, `{"step":"cancel","state":{"rolloutId":"`+id+`","roleName":"`+role+`","error":{"Error":"States.Timeout","Cause":""}}}`)
	w.step(t, `{"step":"mark_failed","state":{"rolloutId":"`+id+`","roleName":"`+role+`","error":{"Error":"States.TaskFailed","Cause":"boom"}}}`)
	want := []string{
		"rollback " + id + " ssm:GetParametersByPath",
		"cancel " + id + ": The PR was closed without merging.",
		"cancel " + id + ": No decision within 7 days, so the proposal expired.",
		"fail " + id + ": States.TaskFailed: boom",
	}
	if !reflect.DeepEqual(w.engine.calls, want) {
		t.Errorf("calls =\n%v\nwant\n%v", w.engine.calls, want)
	}
}

func TestModesAreSeparated(t *testing.T) {
	approver := newWorld(ModeApprover)
	for _, step := range []string{"start", "enforce", "rollback", "watch"} {
		if _, err := approver.d.handle(context.Background(), Input{Step: step, RoleName: role}); !errors.Is(err, errRefused) {
			t.Errorf("approver accepted %q: %v", step, err)
		}
	}
	worker := newWorld(ModeWorker)
	if _, err := worker.d.handle(context.Background(), Input{Step: "approve", RolloutID: id, PRNumber: 3}); !errors.Is(err, errRefused) {
		t.Errorf("worker accepted approve: %v", err)
	}
}

func TestApproveStep(t *testing.T) {
	w := newWorld(ModeApprover)
	w.store.items[id] = store.Rollout{RolloutID: id, RoleName: role, Status: store.StatusPROpen, PRNumber: 3, TaskToken: "tok"}
	w.gh.merged = githubpr.MergeInfo{Merged: true, MergedBy: "singha105", State: "closed"}
	out, err := w.d.handle(context.Background(), Input{Step: "approve", RolloutID: id, PRNumber: 3})
	if err != nil {
		t.Fatal(err)
	}
	if out.(rollout.ApproveResult).Decision != "approved" || w.states.success != 1 || w.store.items[id].Status != store.StatusApproved || w.store.items[id].ApprovedAt != "2026-10-02T08:00:00Z" {
		t.Errorf("approve: %+v, record %+v", out, w.store.items[id])
	}
	if _, err := w.d.handle(context.Background(), Input{Step: "approve", RolloutID: id}); err == nil {
		t.Error("approve without prNumber must fail")
	}
}

func TestDecodeRejectsUnknownFields(t *testing.T) {
	if _, err := decode(json.RawMessage(`{"step":"watch","stat":{}}`)); err == nil {
		t.Error("a typo in the state machine input must fail loudly")
	}
	in, err := decode(json.RawMessage(`{"step":"approve","rolloutId":"x","prNumber":3}`))
	if err != nil || in.PRNumber != 3 || aws.ToString(&in.RolloutID) != "x" {
		t.Errorf("decode approve: %+v %v", in, err)
	}
}
