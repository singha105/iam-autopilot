// Package shadow replays a role's past calls through the IAM policy simulator
// against a proposed policy, to prove nothing it used would be denied.
//
// Known limitation: SimulateCustomPolicy evaluates only the identity policies
// we pass in. It does not apply SCPs, the role's permissions boundary,
// resource policies or session policies, and the other policies attached to
// the role (AWSLambdaBasicExecutionRole) are not included. Shadow mode answers
// "does the proposed managed policy still allow everything the code did?",
// which is the only thing the autopilot changes.
package shadow

import (
	"context"
	"fmt"
	"sort"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"golang.org/x/time/rate"

	"github.com/singha105/iam-autopilot/internal/observe"
	"github.com/singha105/iam-autopilot/internal/policy"
)

// SimulatorAPI is the IAM call shadow mode uses. It is free and read-only.
type SimulatorAPI interface {
	SimulateCustomPolicy(context.Context, *iam.SimulateCustomPolicyInput, ...func(*iam.Options)) (*iam.SimulateCustomPolicyOutput, error)
}

// maxActionsPerRequest keeps each request small; results are paginated anyway.
const maxActionsPerRequest = 50

// Call is one (action, resource) pair to test.
type Call struct {
	Action   string `json:"action"`
	Resource string `json:"resource"`
}

// Denial is a call the simulated policy would not allow.
type Denial struct {
	Action   string `json:"action"`
	Resource string `json:"resource"`
	Decision string `json:"decision"`
}

// Report is the outcome of a replay.
type Report struct {
	Tested   int      `json:"tested"`
	Allowed  int      `json:"allowed"`
	Denied   []Denial `json:"denied"`
	Skipped  []string `json:"skipped"`
	Warnings []string `json:"warnings"`
}

// Replayer runs simulations at most 5 requests per second.
type Replayer struct {
	IAM     SimulatorAPI
	Limiter *rate.Limiter
}

// New returns a Replayer with the production rate limit.
func New(client SimulatorAPI) *Replayer {
	return &Replayer{IAM: client, Limiter: rate.NewLimiter(5, 1)}
}

// TestSet is every observed call (action on its resource) plus every Access
// Advisor tracked action used in the window (on "*"). Actions seen only as
// platform calls (ADR-002) are skipped and listed: the generator removes them
// on purpose, because the function's code never makes them.
func TestSet(p observe.Profile) (calls []Call, skipped []string) {
	set := map[Call]bool{}
	for _, c := range p.ObservedCalls {
		r := c.Resource
		if r == "" {
			r = "*"
		}
		set[Call{Action: c.Action, Resource: r}] = true
	}
	platform := p.ExcludedActions()
	skip := map[string]bool{}
	for _, s := range p.ServicesAccessed {
		for _, a := range s.TrackedActions {
			if a.LastAccessed.Before(p.Window.Start) || a.LastAccessed.After(p.Window.End) {
				continue
			}
			if platform[a.Action] {
				skip[a.Action] = true
				continue
			}
			set[Call{Action: a.Action, Resource: "*"}] = true
		}
	}
	for c := range set {
		calls = append(calls, c)
	}
	sort.Slice(calls, func(i, j int) bool {
		if calls[i].Resource != calls[j].Resource {
			return calls[i].Resource < calls[j].Resource
		}
		return calls[i].Action < calls[j].Action
	})
	for a := range skip {
		skipped = append(skipped, a)
	}
	sort.Strings(skipped)
	return calls, skipped
}

// Replay simulates the profile's test set against the proposed policy.
func (r *Replayer) Replay(ctx context.Context, proposed policy.Document, p observe.Profile) (Report, error) {
	calls, skipped := TestSet(p)
	rep := Report{Denied: []Denial{}, Skipped: append([]string{}, skipped...), Warnings: []string{}}
	if rep.Skipped == nil {
		rep.Skipped = []string{}
	}
	denials, tested, err := r.simulate(ctx, proposed, calls)
	if err != nil {
		return rep, err
	}
	rep.Tested = tested
	rep.Allowed = tested - len(denials)
	rep.Denied = denials
	return rep, nil
}

// ReplayWithSelfTest also replays the same test set against the CURRENT
// policy. If the current policy denies something, the test set is wrong (not
// the proposal), so that is reported as a warning.
func (r *Replayer) ReplayWithSelfTest(ctx context.Context, proposed, current policy.Document, p observe.Profile) (Report, error) {
	rep, err := r.Replay(ctx, proposed, p)
	if err != nil {
		return rep, err
	}
	calls, _ := TestSet(p)
	selfDenied, _, err := r.simulate(ctx, current, calls)
	if err != nil {
		return rep, fmt.Errorf("self-test of the current policy: %w", err)
	}
	for _, d := range selfDenied {
		rep.Warnings = append(rep.Warnings, fmt.Sprintf("self-test: the CURRENT policy also denies %s on %s (%s); the test set is wrong, not the proposal", d.Action, d.Resource, d.Decision))
	}
	return rep, nil
}

// simulate groups calls by resource so each request carries several actions
// and one resource, follows Marker pagination, and returns the denials.
func (r *Replayer) simulate(ctx context.Context, doc policy.Document, calls []Call) ([]Denial, int, error) {
	js, err := doc.Compact()
	if err != nil {
		return nil, 0, err
	}
	byResource := map[string][]string{}
	for _, c := range calls {
		byResource[c.Resource] = append(byResource[c.Resource], c.Action)
	}
	resources := make([]string, 0, len(byResource))
	for res := range byResource {
		resources = append(resources, res)
	}
	sort.Strings(resources)

	denied := []Denial{}
	tested := 0
	for _, res := range resources {
		actions := byResource[res]
		for start := 0; start < len(actions); start += maxActionsPerRequest {
			chunk := actions[start:min(start+maxActionsPerRequest, len(actions))]
			in := &iam.SimulateCustomPolicyInput{
				PolicyInputList: []string{js},
				ActionNames:     chunk,
				ResourceArns:    []string{res},
			}
			for {
				if err := r.Limiter.Wait(ctx); err != nil {
					return nil, 0, err
				}
				out, err := r.IAM.SimulateCustomPolicy(ctx, in)
				if err != nil {
					return nil, 0, fmt.Errorf("simulate %v on %s: %w", chunk, res, err)
				}
				for _, e := range out.EvaluationResults {
					tested++
					if e.EvalDecision != "allowed" {
						denied = append(denied, Denial{Action: aws.ToString(e.EvalActionName), Resource: res, Decision: string(e.EvalDecision)})
					}
				}
				if !out.IsTruncated || out.Marker == nil {
					break
				}
				in.Marker = out.Marker
			}
		}
	}
	sort.Slice(denied, func(i, j int) bool {
		if denied[i].Action != denied[j].Action {
			return denied[i].Action < denied[j].Action
		}
		return denied[i].Resource < denied[j].Resource
	})
	return denied, tested, nil
}
