package rollout

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	cttypes "github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	cwtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/sfn"

	"github.com/singha105/iam-autopilot/internal/config"
	"github.com/singha105/iam-autopilot/internal/githubpr"
	"github.com/singha105/iam-autopilot/internal/store"
)

const (
	roleName  = "iamap-demo-quarterly-role"
	roleARN   = "arn:aws:iam::123456789012:role/iamap-demo-quarterly-role"
	fnName    = "iamap-demo-quarterly"
	policyARN = "arn:aws:iam::123456789012:policy/iamap/managed/iamap-demo-quarterly-policy"
	id        = "iamap-demo-quarterly-role-20261002T060000Z"
	oldDoc    = `{"Statement":[{"Action":["ssm:*"],"Effect":"Allow","Resource":"*"}],"Version":"2012-10-17"}`
	newDoc    = "{\n  \"Statement\": [],\n  \"Version\": \"2012-10-17\"\n}\n"
)

var t0 = time.Date(2026, 10, 2, 6, 0, 0, 0, time.UTC)

// --- fakes ------------------------------------------------------------------

type fakeIAM struct {
	versions  []iamtypes.PolicyVersion
	docs      map[string]string
	tags      map[string]string
	created   []string
	deleted   []string
	defaultTo []string
	next      int
}

func newFakeIAM(n int) *fakeIAM {
	f := &fakeIAM{docs: map[string]string{}, tags: map[string]string{"autopilot:managed": "true"}, next: n + 1}
	for i := 1; i <= n; i++ {
		v := fmt.Sprintf("v%d", i)
		f.versions = append(f.versions, iamtypes.PolicyVersion{VersionId: aws.String(v), IsDefaultVersion: i == n, CreateDate: aws.Time(t0.Add(time.Duration(i) * time.Hour))})
		f.docs[v] = oldDoc
	}
	return f
}

func (f *fakeIAM) def() string {
	for _, v := range f.versions {
		if v.IsDefaultVersion {
			return aws.ToString(v.VersionId)
		}
	}
	return ""
}

func (f *fakeIAM) ListPolicyVersions(context.Context, *iam.ListPolicyVersionsInput, ...func(*iam.Options)) (*iam.ListPolicyVersionsOutput, error) {
	return &iam.ListPolicyVersionsOutput{Versions: append([]iamtypes.PolicyVersion{}, f.versions...)}, nil
}

func (f *fakeIAM) GetPolicyVersion(_ context.Context, in *iam.GetPolicyVersionInput, _ ...func(*iam.Options)) (*iam.GetPolicyVersionOutput, error) {
	return &iam.GetPolicyVersionOutput{PolicyVersion: &iamtypes.PolicyVersion{Document: aws.String(url.QueryEscape(f.docs[aws.ToString(in.VersionId)]))}}, nil
}

func (f *fakeIAM) CreatePolicyVersion(_ context.Context, in *iam.CreatePolicyVersionInput, _ ...func(*iam.Options)) (*iam.CreatePolicyVersionOutput, error) {
	if len(f.versions) >= maxPolicyVersions {
		return nil, errors.New("LimitExceeded: a managed policy can have up to 5 versions")
	}
	v := fmt.Sprintf("v%d", f.next)
	f.next++
	for i := range f.versions {
		f.versions[i].IsDefaultVersion = false
	}
	f.versions = append(f.versions, iamtypes.PolicyVersion{VersionId: aws.String(v), IsDefaultVersion: in.SetAsDefault, CreateDate: aws.Time(t0.Add(48 * time.Hour))})
	f.docs[v] = aws.ToString(in.PolicyDocument)
	f.created = append(f.created, v)
	return &iam.CreatePolicyVersionOutput{PolicyVersion: &iamtypes.PolicyVersion{VersionId: aws.String(v)}}, nil
}

func (f *fakeIAM) DeletePolicyVersion(_ context.Context, in *iam.DeletePolicyVersionInput, _ ...func(*iam.Options)) (*iam.DeletePolicyVersionOutput, error) {
	v := aws.ToString(in.VersionId)
	for i, pv := range f.versions {
		if aws.ToString(pv.VersionId) == v {
			if pv.IsDefaultVersion {
				return nil, errors.New("DeleteConflict: cannot delete the default version")
			}
			f.versions = append(f.versions[:i], f.versions[i+1:]...)
			f.deleted = append(f.deleted, v)
			return &iam.DeletePolicyVersionOutput{}, nil
		}
	}
	return nil, errors.New("NoSuchEntity")
}

func (f *fakeIAM) SetDefaultPolicyVersion(_ context.Context, in *iam.SetDefaultPolicyVersionInput, _ ...func(*iam.Options)) (*iam.SetDefaultPolicyVersionOutput, error) {
	for i := range f.versions {
		f.versions[i].IsDefaultVersion = aws.ToString(f.versions[i].VersionId) == aws.ToString(in.VersionId)
	}
	f.defaultTo = append(f.defaultTo, aws.ToString(in.VersionId))
	return &iam.SetDefaultPolicyVersionOutput{}, nil
}

func (f *fakeIAM) ListRoleTags(context.Context, *iam.ListRoleTagsInput, ...func(*iam.Options)) (*iam.ListRoleTagsOutput, error) {
	var tags []iamtypes.Tag
	for k, v := range f.tags {
		tags = append(tags, iamtypes.Tag{Key: aws.String(k), Value: aws.String(v)})
	}
	return &iam.ListRoleTagsOutput{Tags: tags}, nil
}

type fakeCT struct{ events []cttypes.Event }

func (f *fakeCT) LookupEvents(context.Context, *cloudtrail.LookupEventsInput, ...func(*cloudtrail.Options)) (*cloudtrail.LookupEventsOutput, error) {
	return &cloudtrail.LookupEventsOutput{Events: f.events}, nil
}

func deniedEvent(action, eventName, errorCode string, at time.Time) cttypes.Event {
	src := strings.Split(action, ":")[0] + ".amazonaws.com"
	doc := fmt.Sprintf(`{"eventSource":%q,"eventName":%q,"eventTime":%q,"awsRegion":"us-east-1","recipientAccountId":"123456789012","errorCode":%q,"requestParameters":{"path":"/iamap/demo/quarterly/"},"userIdentity":{"sessionContext":{"sessionIssuer":{"arn":%q}}}}`,
		src, eventName, at.Format(time.RFC3339), errorCode, roleARN)
	return cttypes.Event{EventTime: aws.Time(at), CloudTrailEvent: aws.String(doc)}
}

type fakeCW struct {
	sums []float64
	in   *cloudwatch.GetMetricStatisticsInput
}

func (f *fakeCW) GetMetricStatistics(_ context.Context, in *cloudwatch.GetMetricStatisticsInput, _ ...func(*cloudwatch.Options)) (*cloudwatch.GetMetricStatisticsOutput, error) {
	f.in = in
	var dps []cwtypes.Datapoint
	for _, s := range f.sums {
		dps = append(dps, cwtypes.Datapoint{Sum: aws.Float64(s)})
	}
	return &cloudwatch.GetMetricStatisticsOutput{Datapoints: dps}, nil
}

type memStore struct{ items map[string]store.Rollout }

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

// SetFields round-trips through JSON so every settable attribute works.
func (m *memStore) SetFields(_ context.Context, id string, f map[string]any) error {
	r := m.items[id]
	b, _ := json.Marshal(r)
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

type fakePR struct {
	comments []string
	closed   []string
	reverts  []githubpr.RevertPR
	merged   githubpr.MergeInfo
}

func (f *fakePR) CommentOnPR(_ context.Context, _ int, md string) error {
	f.comments = append(f.comments, md)
	return nil
}

func (f *fakePR) ClosePR(_ context.Context, n int, branch, comment string) error {
	f.closed = append(f.closed, fmt.Sprintf("#%d %s", n, branch))
	f.comments = append(f.comments, comment)
	return nil
}

func (f *fakePR) OpenRevertPR(_ context.Context, in githubpr.RevertPR) (githubpr.Result, error) {
	f.reverts = append(f.reverts, in)
	return githubpr.Result{Number: 9, URL: "https://github.com/o/r/pull/9", Branch: "autopilot-revert/" + in.RolloutID}, nil
}

func (f *fakePR) IsMerged(context.Context, int) (githubpr.MergeInfo, error) { return f.merged, nil }

type fakeStates struct {
	success []string
	failure []string
}

func (f *fakeStates) SendTaskSuccess(_ context.Context, in *sfn.SendTaskSuccessInput, _ ...func(*sfn.Options)) (*sfn.SendTaskSuccessOutput, error) {
	f.success = append(f.success, aws.ToString(in.TaskToken)+" "+aws.ToString(in.Output))
	return &sfn.SendTaskSuccessOutput{}, nil
}

func (f *fakeStates) SendTaskFailure(_ context.Context, in *sfn.SendTaskFailureInput, _ ...func(*sfn.Options)) (*sfn.SendTaskFailureOutput, error) {
	f.failure = append(f.failure, aws.ToString(in.TaskToken)+" "+aws.ToString(in.Error))
	return &sfn.SendTaskFailureOutput{}, nil
}

type harness struct {
	e     *Engine
	iam   *fakeIAM
	ct    *fakeCT
	cw    *fakeCW
	pr    *fakePR
	store *memStore
	clock time.Time
}

func newHarness(versions int, status store.Status) *harness {
	h := &harness{iam: newFakeIAM(versions), ct: &fakeCT{}, cw: &fakeCW{}, pr: &fakePR{}, clock: t0.Add(72 * time.Hour)}
	h.store = &memStore{items: map[string]store.Rollout{id: {
		RolloutID: id, RoleName: roleName, RoleArn: roleARN, FunctionName: fnName, PolicyArn: policyARN,
		Status: status, CurrentVersionID: fmt.Sprintf("v%d", versions), ProposedPolicy: newDoc, PRNumber: 4, PRBranch: "autopilot/" + id,
		CreatedAt: store.Timestamp(t0), Metrics: store.Metrics{GrantedBefore: 532, GrantedAfter: 1, RemovedPercent: 99.8, DeniedActions: []string{}},
	}}}
	cfg := config.Config{
		Roles: []config.Role{{Name: roleName, PolicyFile: "policies/demo/quarterly.json"}},
		Watch: config.Watch{Minutes: 30, LagBufferMinutes: 15, PollSeconds: 300},
	}
	h.e = &Engine{IAM: h.iam, CloudTrail: h.ct, Metrics: h.cw, GitHub: h.pr, Store: h.store, Config: cfg, Now: func() time.Time { return h.clock }}
	return h
}

func (h *harness) rec() store.Rollout { return h.store.items[id] }

// --- enforce ----------------------------------------------------------------

func TestOldestPrunable(t *testing.T) {
	vs := []iamtypes.PolicyVersion{
		{VersionId: aws.String("v7"), CreateDate: aws.Time(t0.Add(7 * time.Hour)), IsDefaultVersion: true},
		{VersionId: aws.String("v4"), CreateDate: aws.Time(t0.Add(4 * time.Hour))},
		{VersionId: aws.String("v2"), CreateDate: aws.Time(t0.Add(2 * time.Hour))},
		{VersionId: aws.String("v6"), CreateDate: aws.Time(t0.Add(6 * time.Hour))},
		{VersionId: aws.String("v3"), CreateDate: aws.Time(t0.Add(3 * time.Hour))},
	}
	if got := OldestPrunable(vs, "v7"); got != "v2" {
		t.Errorf("OldestPrunable = %s, want v2 (oldest non-default)", got)
	}
	if got := OldestPrunable(vs, "v2"); got != "v3" {
		t.Errorf("keep=v2: got %s, want v3 (never the rollback target)", got)
	}
	if got := OldestPrunable(vs[:1], "v7"); got != "" {
		t.Errorf("only the default left: got %q", got)
	}
}

func TestEnforce(t *testing.T) {
	h := newHarness(2, store.StatusApproved)
	res, err := h.e.Enforce(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	r := h.rec()
	if res != (EnforceResult{PrevVersionID: "v2", NewVersionID: "v3"}) || r.Status != store.StatusEnforcedWatching ||
		r.PrevVersionID != "v2" || r.NewVersionID != "v3" || r.EnforcedAt != store.Timestamp(h.clock) {
		t.Errorf("result %+v, record %+v", res, r)
	}
	if h.iam.def() != "v3" || h.iam.docs["v3"] != newDoc || len(h.iam.deleted) != 0 {
		t.Errorf("IAM: default %s, deleted %v", h.iam.def(), h.iam.deleted)
	}
}

func TestEnforcePrunesTheOldestWhenFull(t *testing.T) {
	h := newHarness(5, store.StatusApproved)
	if _, err := h.e.Enforce(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(h.iam.deleted, []string{"v1"}) || h.iam.def() != "v6" || h.rec().PrevVersionID != "v5" {
		t.Errorf("deleted %v, default %s, prev %s", h.iam.deleted, h.iam.def(), h.rec().PrevVersionID)
	}
}

func TestEnforceIsSafeToRetry(t *testing.T) {
	h := newHarness(2, store.StatusApproved)
	// First attempt created v3 but "timed out" before updating the record.
	r := h.rec()
	r.PrevVersionID = "v2"
	h.store.items[id] = r
	h.iam.CreatePolicyVersion(context.Background(), &iam.CreatePolicyVersionInput{PolicyDocument: aws.String(newDoc), SetAsDefault: true})
	h.iam.created = nil

	res, err := h.e.Enforce(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	if len(h.iam.created) != 0 || res.PrevVersionID != "v2" || res.NewVersionID != "v3" || h.rec().Status != store.StatusEnforcedWatching {
		t.Errorf("retry created %v, result %+v", h.iam.created, res)
	}
}

func TestEnforceRefuses(t *testing.T) {
	ctx := context.Background()
	t.Run("role not tagged managed", func(t *testing.T) {
		h := newHarness(2, store.StatusApproved)
		h.iam.tags = map[string]string{}
		_, err := h.e.Enforce(ctx, id)
		if !errors.Is(err, ErrUnsafe) || h.rec().Status != store.StatusFailed || len(h.iam.created) != 0 {
			t.Errorf("err %v, status %s, created %v", err, h.rec().Status, h.iam.created)
		}
	})
	t.Run("policy outside /iamap/managed/", func(t *testing.T) {
		h := newHarness(2, store.StatusApproved)
		r := h.rec()
		r.PolicyArn = "arn:aws:iam::123456789012:policy/someone-else"
		h.store.items[id] = r
		if _, err := h.e.Enforce(ctx, id); !errors.Is(err, ErrUnsafe) || h.rec().Status != store.StatusFailed {
			t.Errorf("err %v, status %s", err, h.rec().Status)
		}
	})
	t.Run("stale proposal", func(t *testing.T) {
		h := newHarness(2, store.StatusApproved)
		r := h.rec()
		r.CurrentVersionID = "v1" // the default moved to v2 after the proposal
		h.store.items[id] = r
		_, err := h.e.Enforce(ctx, id)
		if err == nil || !strings.Contains(err.Error(), "re-run the proposal") || h.rec().Status != store.StatusFailed || len(h.iam.created) != 0 {
			t.Errorf("err %v, status %s", err, h.rec().Status)
		}
	})
	t.Run("not approved", func(t *testing.T) {
		h := newHarness(2, store.StatusPROpen)
		if _, err := h.e.Enforce(ctx, id); err == nil || h.rec().Status != store.StatusPROpen || len(h.iam.created) != 0 {
			t.Errorf("err %v, status %s", err, h.rec().Status)
		}
	})
}

// --- watch ------------------------------------------------------------------

func enforced(h *harness, minutesAgo int) time.Time {
	at := h.clock.Add(-time.Duration(minutesAgo) * time.Minute)
	r := h.rec()
	r.Status, r.EnforcedAt, r.PrevVersionID, r.NewVersionID = store.StatusEnforcedWatching, store.Timestamp(at), "v2", "v3"
	h.store.items[id] = r
	return at
}

func TestWatch(t *testing.T) {
	ctx := context.Background()
	tests := []struct {
		name       string
		minutesAgo int
		denied     bool
		errors     []float64
		want       WatchResult
	}{
		{"no breakage, window open", 10, false, []float64{0, 0}, WatchResult{Iteration: 3, DeniedActions: []string{}}},
		{"no breakage, window over", 46, false, nil, WatchResult{Iteration: 3, DeniedActions: []string{}, Done: true}},
		{"CloudTrail denial only", 10, true, nil, WatchResult{Broken: true, Iteration: 3, DeniedActions: []string{"ssm:GetParametersByPath"}}},
		{"Errors metric only", 10, false, []float64{0, 2, 1}, WatchResult{Broken: true, Iteration: 3, DeniedActions: []string{}, ErrorsSum: 3}},
		{"both signals", 50, true, []float64{1}, WatchResult{Broken: true, Iteration: 3, DeniedActions: []string{"ssm:GetParametersByPath"}, ErrorsSum: 1}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newHarness(2, store.StatusApproved)
			at := enforced(h, tt.minutesAgo)
			if tt.denied {
				h.ct.events = []cttypes.Event{deniedEvent("ssm:GetParametersByPath", "GetParametersByPath", "AccessDenied", at.Add(time.Minute))}
			}
			h.cw.sums = tt.errors
			got, err := h.e.Watch(ctx, id, 2)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Watch = %+v, want %+v", got, tt.want)
			}
			r := h.rec()
			if tt.want.Broken && (r.DetectedAt != store.Timestamp(h.clock) || r.Metrics.DetectSeconds != float64(tt.minutesAgo*60)) {
				t.Errorf("detectedAt %q detectSeconds %v", r.DetectedAt, r.Metrics.DetectSeconds)
			}
			if !tt.want.Broken && r.DetectedAt != "" {
				t.Error("detectedAt set without breakage")
			}
			// The metric query is exactly the free GetMetricStatistics call.
			in := h.cw.in
			if aws.ToString(in.Namespace) != "AWS/Lambda" || aws.ToString(in.MetricName) != "Errors" || aws.ToInt32(in.Period) != 60 ||
				aws.ToString(in.Dimensions[0].Value) != fnName || !in.StartTime.Equal(at) || in.Statistics[0] != cwtypes.StatisticSum {
				t.Errorf("metric query = %+v", in)
			}
		})
	}
}

func TestWatchKeepsTheFirstDetectionTime(t *testing.T) {
	h := newHarness(2, store.StatusApproved)
	enforced(h, 10)
	h.cw.sums = []float64{1}
	if _, err := h.e.Watch(context.Background(), id, 0); err != nil {
		t.Fatal(err)
	}
	first := h.rec().DetectedAt
	h.clock = h.clock.Add(5 * time.Minute)
	if _, err := h.e.Watch(context.Background(), id, 1); err != nil {
		t.Fatal(err)
	}
	if h.rec().DetectedAt != first {
		t.Errorf("detectedAt moved from %s to %s", first, h.rec().DetectedAt)
	}
}

func TestDoneTime(t *testing.T) {
	for minutes, done := range map[int]bool{44: false, 45: true, 60: true} {
		h := newHarness(2, store.StatusApproved)
		enforced(h, minutes)
		got, err := h.e.Watch(context.Background(), id, 0)
		if err != nil || got.Done != done {
			t.Errorf("%d minutes after enforcement: done = %v, want %v (30 + 15 buffer)", minutes, got.Done, done)
		}
	}
}

// --- rollback / complete / cancel / fail -------------------------------------

func TestRollback(t *testing.T) {
	h := newHarness(2, store.StatusApproved)
	if _, err := h.e.Enforce(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	h.clock = h.clock.Add(64 * time.Second)
	r := h.rec()
	r.DetectedAt = store.Timestamp(h.clock)
	h.store.items[id] = r
	h.clock = h.clock.Add(2 * time.Second)

	res, err := h.e.Rollback(context.Background(), id, []string{"ssm:GetParametersByPath"})
	if err != nil {
		t.Fatal(err)
	}
	r = h.rec()
	if h.iam.def() != "v2" || !reflect.DeepEqual(h.iam.defaultTo, []string{"v2"}) || r.Status != store.StatusRolledBack ||
		r.RolledBackAt != store.Timestamp(h.clock) || r.FinishedAt == "" || r.Metrics.RollbackSeconds != 2 || r.Metrics.DetectSeconds != 64 ||
		!reflect.DeepEqual(r.Metrics.DeniedActions, []string{"ssm:GetParametersByPath"}) {
		t.Errorf("record %+v, IAM default %s", r, h.iam.def())
	}
	if res.RestoredVersionID != "v2" || res.RevertPRURL != "https://github.com/o/r/pull/9" || res.Warning != "" {
		t.Errorf("result %+v", res)
	}
	if len(h.pr.comments) != 1 || !strings.Contains(h.pr.comments[0], "`ssm:GetParametersByPath`") || !strings.Contains(h.pr.comments[0], "Detected 64 s") {
		t.Errorf("comment = %v", h.pr.comments)
	}
	rv := h.pr.reverts[0]
	if string(rv.OldPolicyJSON) != oldDoc+"\n" || !reflect.DeepEqual(rv.KeepActions, []string{"ssm:GetParametersByPath"}) || rv.PolicyFile != "policies/demo/quarterly.json" || rv.ConfigPath != "autopilot.yaml" {
		t.Errorf("revert PR = %+v", rv)
	}
}

func TestRollbackOnMetricOnly(t *testing.T) {
	h := newHarness(2, store.StatusApproved)
	enforced(h, 5)
	if _, err := h.e.Rollback(context.Background(), id, nil); err != nil {
		t.Fatal(err)
	}
	if h.iam.def() != "v2" || h.rec().Status != store.StatusRolledBack {
		t.Errorf("default %s, status %s", h.iam.def(), h.rec().Status)
	}
	if !strings.Contains(h.pr.comments[0], "no `AccessDenied` event could be tied to a specific action") || len(h.pr.reverts[0].KeepActions) != 0 {
		t.Errorf("comment %q, keep %v", h.pr.comments[0], h.pr.reverts[0].KeepActions)
	}
}

func TestComplete(t *testing.T) {
	h := newHarness(2, store.StatusApproved)
	enforced(h, 46)
	if err := h.e.Complete(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	r := h.rec()
	if r.Status != store.StatusEnforced || r.FinishedAt == "" || r.PrevVersionID != "v2" || len(h.iam.deleted) != 0 {
		t.Errorf("record %+v, deleted %v", r, h.iam.deleted)
	}
	if c := h.pr.comments; len(c) != 1 || !strings.Contains(c[0], "**Enforced.**") || !strings.Contains(c[0], "532 → 1 (99.8% removed)") ||
		!strings.Contains(c[0], "set-default-policy-version --policy-arn "+policyARN+" --version-id v2") {
		t.Errorf("final comment = %v", c)
	}
}

func TestCancelAndMarkFailed(t *testing.T) {
	h := newHarness(2, store.StatusPROpen)
	if err := h.e.Cancel(context.Background(), id, "PR #4 was closed without merging."); err != nil {
		t.Fatal(err)
	}
	if h.rec().Status != store.StatusCancelled || len(h.pr.closed) != 1 {
		t.Errorf("status %s, closed %v", h.rec().Status, h.pr.closed)
	}
	// FAILED does not overwrite a final status.
	if err := h.e.MarkFailed(context.Background(), id, "boom"); err != nil || h.rec().Status != store.StatusCancelled {
		t.Errorf("MarkFailed on a final rollout: %v, %s", err, h.rec().Status)
	}
	h2 := newHarness(2, store.StatusPROpen)
	if err := h2.e.MarkFailed(context.Background(), id, "observe failed"); err == nil || h2.rec().Status != store.StatusFailed {
		t.Errorf("MarkFailed: %v, %s", err, h2.rec().Status)
	}
}

// --- approve ------------------------------------------------------------------

func TestApprove(t *testing.T) {
	ctx := context.Background()
	setup := func(info githubpr.MergeInfo) (*Approver, *harness, *fakeStates) {
		h := newHarness(2, store.StatusPROpen)
		r := h.rec()
		r.TaskToken = "token-1"
		h.store.items[id] = r
		h.pr.merged = info
		st := &fakeStates{}
		return &Approver{Store: h.store, GitHub: h.pr, States: st}, h, st
	}

	a, h, st := setup(githubpr.MergeInfo{Merged: true, MergedBy: "singha105", State: "closed"})
	res, err := a.Approve(ctx, id, 4, "2026-10-02T07:00:00Z")
	if err != nil || res.Decision != "approved" || h.rec().Status != store.StatusApproved || h.rec().ApprovedAt != "2026-10-02T07:00:00Z" ||
		!reflect.DeepEqual(st.success, []string{`token-1 {"approved":true}`}) {
		t.Errorf("merged: %+v %v, status %s, success %v", res, err, h.rec().Status, st.success)
	}
	// A re-run of the workflow is a no-op.
	if res, err := a.Approve(ctx, id, 4, "later"); err != nil || res.Decision != "already-approved" || len(st.success) != 1 {
		t.Errorf("re-run: %+v %v", res, err)
	}

	a, h, st = setup(githubpr.MergeInfo{Merged: false, State: "closed"})
	if res, err := a.Approve(ctx, id, 4, "x"); err != nil || res.Decision != "cancelled" || !reflect.DeepEqual(st.failure, []string{"token-1 " + ErrorPRClosed}) || h.rec().Status != store.StatusPROpen {
		t.Errorf("closed: %+v %v failure %v", res, err, st.failure)
	}

	a, h, st = setup(githubpr.MergeInfo{State: "open"})
	if _, err := a.Approve(ctx, id, 4, "x"); !errors.Is(err, ErrNotDecided) || len(st.success)+len(st.failure) != 0 || h.rec().Status != store.StatusPROpen {
		t.Errorf("open PR: err %v", err)
	}

	a, _, st = setup(githubpr.MergeInfo{Merged: true, State: "closed"})
	if _, err := a.Approve(ctx, id, 99, "x"); err == nil || len(st.success) != 0 {
		t.Errorf("wrong PR number accepted: %v", err)
	}
}
