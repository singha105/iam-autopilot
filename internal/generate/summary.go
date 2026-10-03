package generate

import (
	"fmt"
	"math"
	"sort"
	"strings"

	"github.com/singha105/iam-autopilot/internal/policy"
)

// Summary explains a proposal: how much it removes, per service, and why.
type Summary struct {
	Role             string           `json:"role"`
	GrantedBefore    int              `json:"grantedBefore"`
	GrantedAfter     int              `json:"grantedAfter"`
	RemovedCount     int              `json:"removedCount"`
	RemovedPercent   float64          `json:"removedPercent"`
	Services         []ServiceSummary `json:"services"`
	Kept             []KeptAction     `json:"kept"`
	KeptUnobservable []KeptAction     `json:"keptUnobservable"`
	Warnings         []string         `json:"warnings"`
	Validation       []Finding        `json:"validation"`
}

// ServiceSummary is one row of the per-service table.
type ServiceSummary struct {
	Service string `json:"service"`
	Before  int    `json:"before"`
	After   int    `json:"after"`
	Rule    string `json:"rule"`
}

// Finding is one Access Analyzer ValidatePolicy finding.
type Finding struct {
	Type      string `json:"type"`
	IssueCode string `json:"issueCode"`
	Message   string `json:"message"`
}

func buildSummary(role string, before, after []string, actions []KeptAction, unchanged map[string][]policy.Statement, used, platformOnly map[string]bool, warnings []string) Summary {
	count := func(list []string) map[string]int {
		m := map[string]int{}
		for _, a := range list {
			m[service(a)]++
		}
		return m
	}
	b, a := count(before), count(after)
	rules := map[string]map[string]bool{}
	for _, k := range actions {
		svc := service(k.Action)
		if rules[svc] == nil {
			rules[svc] = map[string]bool{}
		}
		for _, r := range strings.Split(k.Rule, ",") {
			rules[svc][r] = true
		}
	}

	svcs := map[string]bool{}
	for s := range b {
		svcs[s] = true
	}
	for s := range a {
		svcs[s] = true
	}
	s := Summary{
		Role:             role,
		GrantedBefore:    len(before),
		GrantedAfter:     len(after),
		RemovedCount:     len(before) - len(after),
		Kept:             append([]KeptAction{}, actions...),
		KeptUnobservable: []KeptAction{},
		Warnings:         append([]string{}, warnings...),
		Validation:       []Finding{},
	}
	if len(before) > 0 {
		s.RemovedPercent = math.Round(float64(s.RemovedCount)*1000/float64(len(before))) / 10
	}
	for _, svc := range sortedKeys(svcs) {
		var rule string
		switch {
		case len(unchanged[svc]) > 0:
			rule = RuleUnused + " (used, actions unknown: unchanged)"
		case a[svc] == 0 && platformOnly[svc]:
			rule = RuleUnused + " (only platform calls, ADR-002)"
		case a[svc] == 0 && used[svc]:
			rule = RuleUnused + " (used, nothing kept after " + RuleNeverBroaden + ")"
		case a[svc] == 0:
			rule = RuleUnused + " (unused)"
		default:
			rule = strings.Join(sortedKeys(rules[svc]), ",")
		}
		s.Services = append(s.Services, ServiceSummary{Service: svc, Before: b[svc], After: a[svc], Rule: rule})
	}
	for _, k := range actions {
		if strings.Contains(","+k.Rule+",", ","+RuleBlindSpot+",") {
			s.KeptUnobservable = append(s.KeptUnobservable, k)
		}
	}
	return s
}

// AddValidation records ValidatePolicy findings in the summary.
func (s *Summary) AddValidation(findings []Finding) {
	s.Validation = append(s.Validation, findings...)
	sort.SliceStable(s.Validation, func(i, j int) bool {
		if s.Validation[i].Type != s.Validation[j].Type {
			return s.Validation[i].Type < s.Validation[j].Type
		}
		return s.Validation[i].IssueCode < s.Validation[j].IssueCode
	})
}

// Markdown renders the summary for summary.md and the PR body.
func (s Summary) Markdown() string {
	var b strings.Builder
	fmt.Fprintf(&b, "## Least-privilege proposal for `%s`\n\n", s.Role)
	fmt.Fprintf(&b, "**%d → %d actions granted: %d removed (%.1f%%).**\n\n", s.GrantedBefore, s.GrantedAfter, s.RemovedCount, s.RemovedPercent)

	b.WriteString("| Service | Before | After | Decided by |\n|---|---:|---:|---|\n")
	for _, r := range s.Services {
		fmt.Fprintf(&b, "| %s | %d | %d | %s |\n", r.Service, r.Before, r.After, r.Rule)
	}

	b.WriteString("\n### Kept actions\n\n| Action | Resources | Rule |\n|---|---|---|\n")
	for _, k := range s.Kept {
		fmt.Fprintf(&b, "| `%s` | %s | %s |\n", k.Action, codeList(k.Resources), k.Rule)
	}

	b.WriteString("\n### Kept but unobservable (R4)\n\n")
	if len(s.KeptUnobservable) == 0 {
		b.WriteString("None.\n")
	} else {
		b.WriteString("CloudTrail event history never records these data-plane calls. They are kept because the service was used: a resource of it appears in event history (and the actions are scoped to it), or Access Advisor reports use that no observed call explains. Review them by hand.\n\n")
		for _, k := range s.KeptUnobservable {
			fmt.Fprintf(&b, "- `%s` on %s\n", k.Action, codeList(k.Resources))
		}
	}

	b.WriteString("\n### Validation (Access Analyzer ValidatePolicy)\n\n")
	if len(s.Validation) == 0 {
		b.WriteString("No findings.\n")
	}
	for _, f := range s.Validation {
		fmt.Fprintf(&b, "- **%s** `%s`: %s\n", f.Type, f.IssueCode, f.Message)
	}

	b.WriteString("\n### Warnings\n\n")
	if len(s.Warnings) == 0 {
		b.WriteString("None.\n")
	}
	for _, w := range s.Warnings {
		fmt.Fprintf(&b, "- %s\n", w)
	}
	b.WriteString("\nRules: R1 unused service · R2 observed in CloudTrail · R3 Access Advisor tracked · R4 data-plane blind spot · R5 resource scoping · R6 keep-list · R7 never broaden.\n")
	return b.String()
}

func codeList(items []string) string {
	q := make([]string, len(items))
	for i, it := range items {
		q[i] = "`" + it + "`"
	}
	return strings.Join(q, ", ")
}
