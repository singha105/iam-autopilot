package generate

import (
	"sort"
	"strings"

	"github.com/singha105/iam-autopilot/internal/catalog"
	"github.com/singha105/iam-autopilot/internal/policy"
)

// SameAccess reports whether two policies grant exactly the same actions on
// exactly the same resources (Allow statements, wildcards expanded through
// the catalog). A proposal that only narrows resources is NOT the same
// access: it is still worth a PR. Deny statements must match as written.
func SameAccess(a, b policy.Document, cat *catalog.Catalog) (bool, error) {
	ea, err := effective(a, cat)
	if err != nil {
		return false, err
	}
	eb, err := effective(b, cat)
	if err != nil {
		return false, err
	}
	if len(ea) != len(eb) {
		return false, nil
	}
	for action, res := range ea {
		if eb[action] != res {
			return false, nil
		}
	}
	return denies(a) == denies(b), nil
}

// effective maps each granted action to its sorted, joined resource list.
func effective(d policy.Document, cat *catalog.Catalog) (map[string]string, error) {
	sets := map[string]map[string]bool{}
	for _, s := range d.Statement {
		if !strings.EqualFold(s.Effect, "Allow") {
			continue
		}
		if len(s.NotAction) > 0 {
			return nil, catalog.ErrNotAction
		}
		for _, p := range s.Action {
			for _, a := range cat.Expand(p) {
				if sets[a] == nil {
					sets[a] = map[string]bool{}
				}
				for _, r := range s.Resource {
					sets[a][r] = true
				}
			}
		}
	}
	out := map[string]string{}
	for a, rs := range sets {
		if rs["*"] {
			out[a] = "*"
			continue
		}
		list := make([]string, 0, len(rs))
		for r := range rs {
			list = append(list, r)
		}
		sort.Strings(list)
		out[a] = strings.Join(list, ",")
	}
	return out, nil
}

func denies(d policy.Document) string {
	var parts []string
	for _, s := range d.Statement {
		if strings.EqualFold(s.Effect, "Deny") {
			b, _ := policy.Document{Statement: policy.Statements{s}}.Compact()
			parts = append(parts, b)
		}
	}
	sort.Strings(parts)
	return strings.Join(parts, "\n")
}
