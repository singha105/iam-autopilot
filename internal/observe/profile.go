package observe

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

// BuildProfile observes one role over [start, end): it resolves the role
// (refusing unmanaged ones), reads CloudTrail event history and IAM Access
// Advisor, and combines them into a deterministic usage profile.
func (o *Observer) BuildProfile(ctx context.Context, roleName string, start, end time.Time) (Profile, error) {
	role, err := o.ResolveRole(ctx, roleName)
	if err != nil {
		return Profile{}, err
	}
	events, err := o.Collect(ctx, role, start, end)
	if err != nil {
		return Profile{}, err
	}
	services, err := o.CollectServiceAccess(ctx, role)
	if err != nil {
		return Profile{}, err
	}
	return assemble(role, events, services), nil
}

// assemble combines both sources. A service counts as accessed only if its
// lastAuthenticated falls inside the window; otherwise it is reported with
// lastAuthenticated null. Tracked actions outside the window are dropped.
func assemble(role Role, events EventsResult, services []ServiceAccess) Profile {
	w := events.Window
	inWindow := func(t time.Time) bool { return !t.Before(w.Start) && !t.After(w.End) }

	accessed := 0
	out := make([]ServiceAccess, 0, len(services))
	for _, s := range services {
		sa := ServiceAccess{Namespace: s.Namespace, TrackedActions: []TrackedAction{}}
		if s.LastAuthenticated != nil && inWindow(*s.LastAuthenticated) {
			t := *s.LastAuthenticated
			sa.LastAuthenticated = &t
			accessed++
		}
		for _, a := range s.TrackedActions {
			if inWindow(a.LastAccessed) {
				sa.TrackedActions = append(sa.TrackedActions, a)
			}
		}
		out = append(out, sa)
	}
	sortServices(out)

	warn := newWarningSet(events.Warnings...)
	if accessed == 0 && len(events.Calls) > 0 {
		warn.add(fmt.Sprintf("Access Advisor shows no service used in the window although event history has %d call(s): Access Advisor can lag by up to about 4 hours, re-run later", len(events.Calls)))
	}

	p := Profile{
		RoleARN:          role.ARN,
		RoleName:         role.Name,
		FunctionName:     role.FunctionName,
		Window:           w,
		ObservedCalls:    append([]ObservedCall{}, events.Calls...),
		ServicesAccessed: out,
		DeniedCalls:      append([]DeniedCall{}, events.Denied...),
		Warnings:         warn.sorted(),
		Stats:            events.Stats,
	}
	sortCalls(p.ObservedCalls)
	sortDenied(p.DeniedCalls)
	return p
}

// AccessedServices returns the namespaces with a lastAuthenticated inside the window.
func (p Profile) AccessedServices() []string {
	var out []string
	for _, s := range p.ServicesAccessed {
		if s.LastAuthenticated != nil {
			out = append(out, s.Namespace)
		}
	}
	return out
}

// Encode returns the profile as indented JSON with a trailing newline. Struct
// field order and sorted lists make the bytes deterministic for a given input.
func (p Profile) Encode() ([]byte, error) {
	b, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}
