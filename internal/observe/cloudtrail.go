package observe

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	cttypes "github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
	"github.com/aws/smithy-go"
)

const (
	// eventHistoryRetention is how far back CloudTrail event history goes.
	eventHistoryRetention = 90 * 24 * time.Hour

	lookupPageSize    = 50
	lookupMaxAttempts = 5
	lookupBaseBackoff = 500 * time.Millisecond
)

// EventsResult is everything CollectEvents learns from event history.
type EventsResult struct {
	Window   Window
	Calls    []ObservedCall
	Denied   []DeniedCall
	Warnings []string
	Stats    Stats
}

// CollectEvents returns the calls the role made in [start, end), aggregated
// per (action, resource), and the calls that were denied. See Collect.
func (o *Observer) CollectEvents(ctx context.Context, role Role, start, end time.Time) ([]ObservedCall, []DeniedCall, error) {
	r, err := o.Collect(ctx, role, start, end)
	return r.Calls, r.Denied, err
}

// Collect reads CloudTrail event history for the role's function and returns
// the aggregated calls, denials, warnings and stats.
//
// An event is used only if its session issuer is exactly the role's ARN; the
// same username from another role is ignored. Calls made by AWS rather than
// by the function's code are excluded and summarised as a warning; see
// platformCaller.
func (o *Observer) Collect(ctx context.Context, role Role, start, end time.Time) (EventsResult, error) {
	var res EventsResult
	w, warnings, err := o.clampWindow(start, end)
	if err != nil {
		return res, err
	}
	res.Window = w
	warn := newWarningSet(warnings...)

	type key struct{ action, resource string }
	calls := map[key]*ObservedCall{}
	otherIssuers := 0
	platformCalls := map[string]int{}

	in := &cloudtrail.LookupEventsInput{
		LookupAttributes: []cttypes.LookupAttribute{{
			AttributeKey:   cttypes.LookupAttributeKeyUsername,
			AttributeValue: aws.String(role.FunctionName),
		}},
		StartTime:  aws.Time(w.Start),
		EndTime:    aws.Time(w.End),
		MaxResults: aws.Int32(lookupPageSize),
	}
	for {
		page, err := o.lookupPage(ctx, in)
		if err != nil {
			return res, err
		}
		res.Stats.PagesFetched++

		for _, e := range page.Events {
			res.Stats.EventsScanned++
			var ev trailEvent
			if err := json.Unmarshal([]byte(aws.ToString(e.CloudTrailEvent)), &ev); err != nil {
				warn.add(fmt.Sprintf("skipped event %s: unparseable CloudTrailEvent: %v", aws.ToString(e.EventId), err))
				continue
			}
			if ev.UserIdentity.SessionContext.SessionIssuer.ARN != role.ARN {
				otherIssuers++
				continue
			}
			action, actionWarning := ActionFor(ev.EventSource, ev.EventName)
			if by := platformCaller(ev); by != "" {
				platformCalls[action+" by "+by]++
				continue
			}
			if actionWarning != "" {
				warn.add(actionWarning)
			}

			at := ev.EventTime.UTC()
			if at.IsZero() && e.EventTime != nil {
				at = e.EventTime.UTC()
			}
			resources := extractResources(ev, e.Resources)

			if ev.ErrorCode != "" && IsDenied(ev.ErrorCode) {
				for _, r := range resources {
					res.Denied = append(res.Denied, DeniedCall{Action: action, Resource: r, ErrorCode: ev.ErrorCode, Time: at})
				}
				continue
			}

			readOnly := ev.ReadOnly != nil && *ev.ReadOnly
			if ev.ReadOnly == nil {
				readOnly = aws.ToString(e.ReadOnly) == "true"
			}
			for _, r := range resources {
				k := key{action, r}
				c, ok := calls[k]
				if !ok {
					c = &ObservedCall{Action: action, Resource: r, FirstSeen: at, LastSeen: at, ReadOnly: readOnly}
					calls[k] = c
				}
				c.Count++
				if at.Before(c.FirstSeen) {
					c.FirstSeen = at
				}
				if at.After(c.LastSeen) {
					c.LastSeen = at
				}
				// A pair counts as read-only only if every call was.
				c.ReadOnly = c.ReadOnly && readOnly
			}
		}

		if page.NextToken == nil || *page.NextToken == "" {
			break
		}
		in.NextToken = page.NextToken
	}

	if otherIssuers > 0 {
		warn.add(fmt.Sprintf("ignored %d event(s) with username %s but a different session issuer than %s", otherIssuers, role.FunctionName, role.ARN))
	}
	for what, n := range platformCalls {
		warn.add(fmt.Sprintf("excluded %d platform call(s): %s (made by AWS with the role's credentials, not by the function's code)", n, what))
	}

	res.Calls = make([]ObservedCall, 0, len(calls))
	for _, c := range calls {
		res.Calls = append(res.Calls, *c)
	}
	sortCalls(res.Calls)
	sortDenied(res.Denied)
	res.Warnings = warn.sorted()

	o.Log.Info("cloudtrail event history read",
		"role", role.Name, "username", role.FunctionName,
		"pages", res.Stats.PagesFetched, "events", res.Stats.EventsScanned,
		"calls", len(res.Calls), "denied", len(res.Denied))
	return res, nil
}

// lambdaWorkerAgent is the user agent of the Lambda runtime's own calls.
const lambdaWorkerAgent = "awslambda-worker"

// platformCaller names who made a call when it was AWS rather than the
// function's code, or returns "" for the function's own calls. Seen in this
// account's event history (PROGRESS.md, Day 1 and Day 2 findings):
//
//   - userIdentity.invokedBy set: a service calling downstream on the role's
//     behalf, e.g. Lambda decrypting other functions' environment variables to
//     answer the role's own lambda:ListFunctions.
//   - user agent awslambda-worker: the Lambda runtime creating the function's
//     log stream at cold start (allowed by AWSLambdaBasicExecutionRole, which
//     the autopilot never edits).
//   - kms:Decrypt with the aws:lambda:FunctionArn encryption context: the
//     Lambda runtime decrypting the function's own environment variables at
//     cold start. It succeeds without any kms permission on the role.
func platformCaller(ev trailEvent) string {
	if by := ev.UserIdentity.InvokedBy; by != "" {
		return by
	}
	if strings.HasPrefix(ev.UserAgent, lambdaWorkerAgent) {
		return "the Lambda runtime (" + lambdaWorkerAgent + ")"
	}
	if ev.EventSource == "kms.amazonaws.com" && ev.EventName == "Decrypt" {
		if ctx, ok := ev.RequestParameters["encryptionContext"].(map[string]any); ok {
			if _, ok := ctx["aws:lambda:FunctionArn"]; ok {
				return "the Lambda runtime (environment variable decryption)"
			}
		}
	}
	return ""
}

// clampWindow moves start forward to the 90-day event history limit, caps end
// at now, and truncates both to whole seconds in UTC.
func (o *Observer) clampWindow(start, end time.Time) (Window, []string, error) {
	now := o.Now().UTC().Truncate(time.Second)
	var warnings []string
	if end.IsZero() || end.After(now) {
		end = now
	}
	if earliest := now.Add(-eventHistoryRetention); start.Before(earliest) {
		start = earliest
		warnings = append(warnings, "window start clamped to 90 days ago: CloudTrail event history keeps 90 days")
	}
	w := Window{Start: start.UTC().Truncate(time.Second), End: end.UTC().Truncate(time.Second)}
	if !w.Start.Before(w.End) {
		return w, nil, fmt.Errorf("empty observation window: start %s is not before end %s", w.Start.Format(time.RFC3339), w.End.Format(time.RFC3339))
	}
	return w, warnings, nil
}

// lookupPage fetches one page, waiting on the rate limiter before every
// attempt and retrying ThrottlingException with exponential backoff.
func (o *Observer) lookupPage(ctx context.Context, in *cloudtrail.LookupEventsInput) (*cloudtrail.LookupEventsOutput, error) {
	backoff := lookupBaseBackoff
	for attempt := 1; ; attempt++ {
		if err := o.Limiter.Wait(ctx); err != nil {
			return nil, err
		}
		out, err := o.CloudTrail.LookupEvents(ctx, in)
		if err == nil {
			return out, nil
		}
		if !isThrottling(err) || attempt == lookupMaxAttempts {
			return nil, fmt.Errorf("cloudtrail LookupEvents (attempt %d of %d): %w", attempt, lookupMaxAttempts, err)
		}
		o.Log.Warn("LookupEvents throttled, backing off", "attempt", attempt, "backoff", backoff.String())
		if err := o.Sleep(ctx, backoff); err != nil {
			return nil, err
		}
		backoff *= 2
	}
}

func isThrottling(err error) bool {
	var apiErr smithy.APIError
	return errors.As(err, &apiErr) && apiErr.ErrorCode() == "ThrottlingException"
}

func sortCalls(cs []ObservedCall) {
	sort.Slice(cs, func(i, j int) bool {
		if cs[i].Action != cs[j].Action {
			return cs[i].Action < cs[j].Action
		}
		return cs[i].Resource < cs[j].Resource
	})
}

func sortDenied(ds []DeniedCall) {
	sort.Slice(ds, func(i, j int) bool {
		a, b := ds[i], ds[j]
		if !a.Time.Equal(b.Time) {
			return a.Time.Before(b.Time)
		}
		if a.Action != b.Action {
			return a.Action < b.Action
		}
		if a.Resource != b.Resource {
			return a.Resource < b.Resource
		}
		return a.ErrorCode < b.ErrorCode
	})
}

// warningSet de-duplicates warnings and returns them sorted.
type warningSet map[string]bool

func newWarningSet(ws ...string) warningSet {
	s := warningSet{}
	for _, w := range ws {
		s.add(w)
	}
	return s
}

func (s warningSet) add(w string) {
	if w = strings.TrimSpace(w); w != "" {
		s[w] = true
	}
}

func (s warningSet) sorted() []string {
	out := make([]string, 0, len(s))
	for w := range s {
		out = append(out, w)
	}
	sort.Strings(out)
	return out
}
