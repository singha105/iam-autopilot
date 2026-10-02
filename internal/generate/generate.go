package generate

import (
	"fmt"
	"sort"
	"strings"

	"github.com/singha105/iam-autopilot/internal/catalog"
	"github.com/singha105/iam-autopilot/internal/config"
	"github.com/singha105/iam-autopilot/internal/observe"
	"github.com/singha105/iam-autopilot/internal/policy"
)

// Rule IDs. Each kept action records the first rule that kept it, and the
// summary shows them so a PR reader can see why every line exists.
const (
	RuleUnused       = "R1" // service unused in the window: all its actions removed
	RuleObserved     = "R2" // action seen in CloudTrail event history
	RuleTracked      = "R3" // action reported by Access Advisor action-level tracking
	RuleBlindSpot    = "R4" // data-plane action of a used service, kept unobservable
	RuleScoped       = "R5" // resources narrowed to observed ARNs the action supports
	RuleKeepList     = "R6" // keepActions / neverRemove from autopilot.yaml
	RuleNeverBroaden = "R7" // result never grants more than the current policy
)

// Result is a proposed policy and the summary explaining it.
type Result struct {
	Policy     policy.Document
	PolicyJSON []byte
	Summary    Summary
}

// kept is one action the proposal keeps.
type kept struct {
	rule         string
	resources    map[string]bool
	unobservable bool
}

type generator struct {
	cat    *catalog.Catalog
	allows []policy.Statement
	kept   map[string]*kept // canonical action -> kept
	// unchanged holds current patterns copied as-is for services that were used
	// but whose actions cannot be identified (see R1 in Generate).
	unchanged map[string][]policy.Statement
	warn      map[string]bool
}

// Generate turns the current policy and a usage profile into a smaller policy.
// It is a pure function: no AWS calls. The rules, in order:
//
//	R1 A service with no Access Advisor activity in the window and no observed
//	   call loses every action. A service whose only activity is platform calls
//	   (ADR-002) counts as unused. A service that WAS used but where no rule can
//	   identify an action (no tracking, nothing observed, no data-plane config)
//	   is left unchanged, with a warning, rather than guessed at.
//	R2 Every observed action is kept, with the resources it was seen on.
//	R3 Every Access Advisor tracked action used in the window is kept ("*"),
//	   unless it was only ever a platform call.
//	R4 For a used service, the configured data-plane actions (per-role override
//	   first) that the current policy grants are kept and marked
//	   kept-unobservable: scoped to concrete ARNs observed for that service, or
//	   "*" if the service had no observed call at all. If it was seen only via
//	   calls on "*", they are not kept and a warning says so (ADR-003).
//	R5 Resources: an action that supports resources keeps the observed ARNs
//	   that fit its resource types; otherwise "*".
//	R6 keepActions and neverRemove from autopilot.yaml are always kept.
//	R7 Never broaden: an action the current policy does not grant is dropped,
//	   a resource it does not cover is narrowed to what it covers, and Deny
//	   statements are copied unchanged.
func Generate(current policy.Document, profile observe.Profile, cfg config.Config, cat *catalog.Catalog) (Result, error) {
	roleCfg, ok := cfg.Role(profile.RoleName)
	if !ok {
		return Result{}, fmt.Errorf("role %s is not listed in autopilot.yaml", profile.RoleName)
	}
	g := &generator{cat: cat, kept: map[string]*kept{}, unchanged: map[string][]policy.Statement{}, warn: map[string]bool{}}
	var denies []policy.Statement
	for _, s := range current.Statement {
		switch {
		case strings.EqualFold(s.Effect, "Deny"):
			denies = append(denies, s)
		case len(s.NotAction) > 0:
			return Result{}, fmt.Errorf("statement %q: %w", s.Sid, catalog.ErrNotAction)
		case len(s.NotResource) > 0:
			return Result{}, fmt.Errorf("statement %q: NotResource in an Allow statement is not supported", s.Sid)
		case len(s.Condition) > 0:
			// Dropping a condition would broaden access (R7); refuse instead.
			return Result{}, fmt.Errorf("statement %q: Allow statements with a Condition are not supported", s.Sid)
		default:
			g.allows = append(g.allows, s)
		}
	}
	before, err := cat.Granted(current)
	if err != nil {
		return Result{}, err
	}

	observedBySvc := map[string][]observe.ObservedCall{}
	for _, c := range profile.ObservedCalls {
		observedBySvc[service(c.Action)] = append(observedBySvc[service(c.Action)], c)
	}
	platformOnly := profile.ExcludedActions()
	used := map[string]bool{}            // services used by the function's code in the window
	platformOnlySvc := map[string]bool{} // used only by AWS on the role's behalf
	for _, s := range profile.ServicesAccessed {
		if s.LastAuthenticated == nil {
			continue
		}
		if len(observedBySvc[s.Namespace]) == 0 && len(s.TrackedActions) > 0 && allIn(s.TrackedActions, platformOnly) {
			platformOnlySvc[s.Namespace] = true
			continue
		}
		used[s.Namespace] = true
	}
	for svc := range observedBySvc {
		used[svc] = true
	}

	// R2: observed actions, with the resources they were seen on.
	for _, c := range profile.ObservedCalls {
		g.add(c.Action, RuleObserved, false, c.Resource)
	}
	// R3: tracked actions used in the window.
	for _, s := range profile.ServicesAccessed {
		if !used[s.Namespace] {
			continue
		}
		for _, a := range s.TrackedActions {
			if platformOnly[a.Action] {
				continue
			}
			if _, ok := g.kept[g.canonical(a.Action)]; !ok {
				g.add(a.Action, RuleTracked, false, "*")
			}
		}
	}
	// R4: the data-plane blind spot (ADR-003). Data-plane actions are kept
	// only with evidence: a concrete resource of the service was observed
	// (scope to it), or the service was used with no observed call at all
	// (pure data-plane use, "*"). A service seen only through calls on "*"
	// (listing buckets, say) gets nothing extra: keeping s3:GetObject on every
	// bucket because the code listed buckets would be a guess, not evidence.
	for _, svc := range sortedKeys(used) {
		var candidates []string
		for _, a := range cfg.DataPlaneFor(profile.RoleName, svc) {
			if _, ok := g.kept[g.canonical(a)]; !ok && g.grantedByCurrent(a) {
				candidates = append(candidates, a)
			}
		}
		if len(candidates) == 0 {
			continue
		}
		var concrete []string
		for _, c := range observedBySvc[svc] {
			if c.Resource != "*" {
				concrete = append(concrete, c.Resource)
			}
		}
		if len(observedBySvc[svc]) > 0 && len(concrete) == 0 {
			g.warnf("R4: %s was used only through calls on \"*\" (no resource seen), so its data-plane actions were not kept: %s. Add keepActions if the code needs them.", svc, strings.Join(candidates, ", "))
			continue
		}
		for _, a := range candidates {
			var res []string
			for _, r := range concrete {
				if cat.ARNFitsAction(a, r) {
					res = append(res, r)
				}
			}
			if len(res) == 0 {
				res = []string{"*"}
			}
			g.add(a, RuleBlindSpot, true, res...)
		}
	}
	// R6: keep-lists.
	for _, k := range append(append([]config.KeepEntry{}, roleCfg.KeepActions...), cfg.NeverRemove...) {
		g.add(k.Action, RuleKeepList, false, k.ResourceOrStar())
	}
	// R1: used services with nothing identified are left unchanged.
	keptSvc := map[string]bool{}
	for a := range g.kept {
		keptSvc[service(a)] = true
	}
	for _, svc := range sortedKeys(used) {
		if keptSvc[svc] {
			continue
		}
		for _, s := range g.allows {
			var actions policy.Strings
			for _, p := range s.Action {
				if strings.EqualFold(service(p), svc) {
					actions = append(actions, p)
				}
			}
			if len(actions) > 0 {
				g.unchanged[svc] = append(g.unchanged[svc], policy.Statement{Effect: "Allow", Action: actions, Resource: s.Resource})
			}
		}
		if len(g.unchanged[svc]) > 0 {
			g.warnf("R1: %s was used in the window but no action could be identified (no tracking, no observed call, no data-plane config); its current grants are left unchanged. Add keepActions to tighten it.", svc)
		}
	}
	for _, d := range profile.DeniedCalls {
		g.warnf("the role was denied %s on %s at %s; denied calls are not added", d.Action, d.Resource, d.Time.Format("2006-01-02T15:04:05Z"))
	}

	actions := g.finalize()
	doc := buildDocument(actions, g.unchanged, denies)
	b, err := doc.Encode()
	if err != nil {
		return Result{}, err
	}
	if n := policy.NonWhitespaceLen(b); n > policy.MaxManagedPolicyChars {
		g.warnf("proposed policy is %d characters (limit %d); merged statements per service", n, policy.MaxManagedPolicyChars)
		doc = mergePerService(doc)
		if b, err = doc.Encode(); err != nil {
			return Result{}, err
		}
		if n := policy.NonWhitespaceLen(b); n > policy.MaxManagedPolicyChars {
			return Result{}, fmt.Errorf("proposed policy is %d characters even after merging (limit %d)", n, policy.MaxManagedPolicyChars)
		}
	}

	after, err := cat.Granted(doc)
	if err != nil {
		return Result{}, err
	}
	summary := buildSummary(profile.RoleName, before, after, actions, g.unchanged, used, platformOnlySvc, g.warnings())
	return Result{Policy: doc, PolicyJSON: b, Summary: summary}, nil
}

func (g *generator) canonical(action string) string {
	if c := g.cat.Canonical(action); c != "" {
		return c
	}
	return action
}

func (g *generator) add(action, rule string, unobservable bool, resources ...string) {
	a := g.canonical(action)
	k, ok := g.kept[a]
	if !ok {
		k = &kept{rule: rule, resources: map[string]bool{}, unobservable: unobservable}
		g.kept[a] = k
	}
	for _, r := range resources {
		k.resources[r] = true
	}
}

func (g *generator) grantedByCurrent(action string) bool {
	return len(g.coveringStatements(action)) > 0
}

// coveringStatements are the current Allow statements that grant the action.
func (g *generator) coveringStatements(action string) []policy.Statement {
	var out []policy.Statement
	for _, s := range g.allows {
		for _, p := range s.Action {
			if catalog.Matches(p, action) {
				out = append(out, s)
				break
			}
		}
	}
	return out
}

func (g *generator) warnf(format string, args ...any) { g.warn[fmt.Sprintf(format, args...)] = true }

func (g *generator) warnings() []string { return sortedKeys(g.warn) }

// KeptAction is one action in the proposal, with the rule that kept it.
type KeptAction struct {
	Action    string   `json:"action"`
	Resources []string `json:"resources"`
	Rule      string   `json:"rule"`
}

// finalize applies R7 (never broaden) and R5 (resource scoping) to every kept
// action and returns them sorted.
func (g *generator) finalize() []KeptAction {
	var out []KeptAction
	for _, a := range sortedKeys(g.kept) {
		k := g.kept[a]
		covering := g.coveringStatements(a)
		if len(covering) == 0 {
			g.warnf("R7: dropped %s (kept by %s): the current policy does not grant it; it probably comes from another attached policy such as AWSLambdaBasicExecutionRole", a, k.rule)
			continue
		}
		rule := k.rule
		res := g.scope(a, k.resources)
		if rule != RuleBlindSpot && !(len(res) == 1 && res[0] == "*") && g.cat.SupportsResources(a) {
			rule += "," + RuleScoped
		}
		res = g.neverBroaden(a, res, covering)
		out = append(out, KeptAction{Action: a, Resources: res, Rule: rule})
	}
	return out
}

// scope applies R5: keep only ARNs that fit one of the action's resource
// types; "*" if the action supports none, or if any resource is already "*".
func (g *generator) scope(action string, resources map[string]bool) []string {
	if resources["*"] || !g.cat.SupportsResources(action) {
		return []string{"*"}
	}
	var out []string
	for _, r := range sortedKeys(resources) {
		if g.cat.ARNFitsAction(action, r) {
			out = append(out, r)
		} else {
			g.warnf("R5: %s cannot be scoped to %s (not one of its resource types); using \"*\"", action, r)
			return []string{"*"}
		}
	}
	return out
}

// neverBroaden applies R7 to resources: every resource must be covered by a
// current Allow statement for the action; otherwise the action is narrowed to
// the resources the current policy grants it on.
func (g *generator) neverBroaden(action string, res []string, covering []policy.Statement) []string {
	allCovered := true
	for _, r := range res {
		ok := false
		for _, s := range covering {
			for _, cr := range s.Resource {
				if cr == "*" || (r != "*" && catalog.Matches(cr, r)) {
					ok = true
				}
			}
		}
		allCovered = allCovered && ok
	}
	if allCovered {
		return res
	}
	set := map[string]bool{}
	for _, s := range covering {
		for _, cr := range s.Resource {
			set[cr] = true
		}
	}
	narrowed := sortedKeys(set)
	g.warnf("R7: %s on %v is not covered by the current policy; narrowed to %v", action, res, narrowed)
	return narrowed
}

// buildDocument groups actions into one statement per (service, identical
// resource set), Sid = service prefix + index, everything sorted.
func buildDocument(actions []KeptAction, unchanged map[string][]policy.Statement, denies []policy.Statement) policy.Document {
	type group struct {
		svc       string
		resources []string
		actions   []string
	}
	groups := map[string]*group{}
	for _, a := range actions {
		key := service(a.Action) + "|" + strings.Join(a.Resources, ",")
		gr, ok := groups[key]
		if !ok {
			gr = &group{svc: service(a.Action), resources: a.Resources}
			groups[key] = gr
		}
		gr.actions = append(gr.actions, a.Action)
	}
	for svc, stmts := range unchanged {
		for _, s := range stmts {
			res := append([]string{}, s.Resource...)
			sort.Strings(res)
			key := svc + "|" + strings.Join(res, ",")
			gr, ok := groups[key]
			if !ok {
				gr = &group{svc: svc, resources: res}
				groups[key] = gr
			}
			gr.actions = append(gr.actions, s.Action...)
		}
	}

	bySvc := map[string][]*group{}
	for _, key := range sortedKeys(groups) {
		gr := groups[key]
		bySvc[gr.svc] = append(bySvc[gr.svc], gr)
	}
	var stmts policy.Statements
	for _, svc := range sortedKeys(bySvc) {
		for i, gr := range bySvc[svc] {
			acts := dedupeSorted(gr.actions)
			stmts = append(stmts, policy.Statement{
				Sid:      sidPrefix(svc) + fmt.Sprint(i),
				Effect:   "Allow",
				Action:   acts,
				Resource: dedupeSorted(gr.resources),
			})
		}
	}
	stmts = append(stmts, denies...)
	sort.SliceStable(stmts, func(i, j int) bool { return stmts[i].Sid < stmts[j].Sid })
	return policy.Document{Version: policy.Version, Statement: stmts}
}

// mergePerService collapses each service's Allow statements into one with
// the union of resources ("*" absorbs everything). Used only when the policy
// is over the size limit.
func mergePerService(doc policy.Document) policy.Document {
	type merged struct {
		actions, resources map[string]bool
	}
	m := map[string]*merged{}
	var out policy.Statements
	for _, s := range doc.Statement {
		if s.Effect != "Allow" {
			out = append(out, s)
			continue
		}
		svc := service(s.Action[0])
		mm, ok := m[svc]
		if !ok {
			mm = &merged{actions: map[string]bool{}, resources: map[string]bool{}}
			m[svc] = mm
		}
		for _, a := range s.Action {
			mm.actions[a] = true
		}
		for _, r := range s.Resource {
			mm.resources[r] = true
		}
	}
	for _, svc := range sortedKeys(m) {
		res := sortedKeys(m[svc].resources)
		if m[svc].resources["*"] {
			res = []string{"*"}
		}
		out = append(out, policy.Statement{Sid: sidPrefix(svc) + "0", Effect: "Allow", Action: sortedKeys(m[svc].actions), Resource: res})
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Sid < out[j].Sid })
	return policy.Document{Version: policy.Version, Statement: out}
}

func service(action string) string {
	svc, _, _ := strings.Cut(action, ":")
	return strings.ToLower(svc)
}

// sidPrefix turns "ssm" into "Ssm" (Sids must be alphanumeric).
func sidPrefix(svc string) string {
	var b strings.Builder
	for i, r := range svc {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9') {
			continue
		}
		if i == 0 {
			r = []rune(strings.ToUpper(string(r)))[0]
		}
		b.WriteRune(r)
	}
	return b.String()
}

func allIn(tracked []observe.TrackedAction, set map[string]bool) bool {
	for _, a := range tracked {
		if !set[a.Action] {
			return false
		}
	}
	return true
}

func dedupeSorted(in []string) []string {
	set := map[string]bool{}
	for _, s := range in {
		set[s] = true
	}
	return sortedKeys(set)
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
