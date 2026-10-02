package catalog

import (
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"sync"

	"github.com/singha105/iam-autopilot/internal/policy"
)

//go:embed data/actions.json
var embedded []byte

// ErrNotAction is returned for Allow statements that use NotAction, which the
// autopilot does not reason about.
var ErrNotAction = errors.New("NotAction in an Allow statement is not supported")

// file mirrors data/actions.json, written by internal/catalog/gen.
type file struct {
	Source   string `json:"source"`
	Services map[string]struct {
		Version string `json:"version"`
		Actions []struct {
			Action        string   `json:"action"`
			ResourceTypes []string `json:"resourceTypes"`
		} `json:"actions"`
		ResourceTypes []struct {
			Name       string   `json:"name"`
			ARNFormats []string `json:"arnFormats"`
		} `json:"resourceTypes"`
	} `json:"services"`
}

type action struct {
	name          string           // canonical "service:Action"
	resourceTypes []string         // empty = Resource "*" only
	arnPatterns   []*regexp.Regexp // ARN formats of those resource types
}

// Catalog answers questions about IAM actions. It is read-only and safe for
// concurrent use.
type Catalog struct {
	actions map[string]*action // key: lower-case "service:action"
	all     []string           // canonical names, sorted
}

var (
	defaultOnce sync.Once
	defaultCat  *Catalog
	defaultErr  error
)

// Default returns the catalog embedded in the binary.
func Default() (*Catalog, error) {
	defaultOnce.Do(func() { defaultCat, defaultErr = Load(embedded) })
	return defaultCat, defaultErr
}

// Load builds a catalog from the actions.json format.
func Load(b []byte) (*Catalog, error) {
	var f file
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, fmt.Errorf("catalog: %w", err)
	}
	c := &Catalog{actions: map[string]*action{}}
	for prefix, svc := range f.Services {
		formats := map[string][]*regexp.Regexp{}
		for _, rt := range svc.ResourceTypes {
			for _, f := range rt.ARNFormats {
				formats[rt.Name] = append(formats[rt.Name], arnFormatRegexp(f))
			}
		}
		for _, a := range svc.Actions {
			name := prefix + ":" + a.Action
			act := &action{name: name, resourceTypes: a.ResourceTypes}
			for _, rt := range a.ResourceTypes {
				act.arnPatterns = append(act.arnPatterns, formats[rt]...)
			}
			c.actions[strings.ToLower(name)] = act
			c.all = append(c.all, name)
		}
	}
	sort.Strings(c.all)
	return c, nil
}

// arnFormatRegexp turns "arn:${Partition}:ssm:${Region}:${Account}:parameter/${Name}"
// into an anchored regexp. Partition, region and account match one ARN field;
// every other variable matches one or more characters.
func arnFormatRegexp(format string) *regexp.Regexp {
	var b strings.Builder
	b.WriteString("^")
	for rest := format; rest != ""; {
		i := strings.Index(rest, "${")
		if i < 0 {
			b.WriteString(regexp.QuoteMeta(rest))
			break
		}
		b.WriteString(regexp.QuoteMeta(rest[:i]))
		j := strings.Index(rest[i:], "}")
		if j < 0 {
			b.WriteString(regexp.QuoteMeta(rest[i:]))
			break
		}
		switch rest[i+2 : i+j] {
		case "Partition", "Region", "Account":
			b.WriteString("[^:]*")
		default:
			b.WriteString(".+")
		}
		rest = rest[i+j+1:]
	}
	b.WriteString("$")
	return regexp.MustCompile(b.String())
}

// Matches reports whether an IAM action pattern (with * and ? wildcards)
// matches an action. Matching is case-insensitive, as in IAM.
func Matches(pattern, action string) bool {
	return wildcard(pattern).MatchString(action)
}

var (
	wildcardMu    sync.Mutex
	wildcardCache = map[string]*regexp.Regexp{}
)

func wildcard(pattern string) *regexp.Regexp {
	wildcardMu.Lock()
	defer wildcardMu.Unlock()
	if re, ok := wildcardCache[pattern]; ok {
		return re
	}
	q := regexp.QuoteMeta(pattern)
	q = strings.ReplaceAll(q, `\*`, `.*`)
	q = strings.ReplaceAll(q, `\?`, `.`)
	re := regexp.MustCompile(`(?i)^` + q + `$`)
	wildcardCache[pattern] = re
	return re
}

// Expand returns every catalog action the pattern matches, sorted and in
// canonical case. "*" alone expands to the whole catalog. Patterns for
// services outside the catalog expand to nothing.
func (c *Catalog) Expand(pattern string) []string {
	if pattern == "*" {
		return append([]string{}, c.all...)
	}
	if !strings.ContainsAny(pattern, "*?") {
		if a, ok := c.actions[strings.ToLower(pattern)]; ok {
			return []string{a.name}
		}
		return nil
	}
	var out []string
	re := wildcard(pattern)
	for _, name := range c.all {
		if re.MatchString(name) {
			out = append(out, name)
		}
	}
	return out
}

// Exists reports whether the action is in the catalog.
func (c *Catalog) Exists(action string) bool {
	_, ok := c.actions[strings.ToLower(action)]
	return ok
}

// Canonical returns the catalog spelling of an action, or "" if unknown.
func (c *Catalog) Canonical(action string) string {
	if a, ok := c.actions[strings.ToLower(action)]; ok {
		return a.name
	}
	return ""
}

// SupportsResources reports whether the action can be scoped to resource ARNs.
// False means it only supports Resource "*" (or is unknown).
func (c *Catalog) SupportsResources(action string) bool {
	a, ok := c.actions[strings.ToLower(action)]
	return ok && len(a.resourceTypes) > 0
}

// ResourceTypes returns the resource types the action supports.
func (c *Catalog) ResourceTypes(action string) []string {
	if a, ok := c.actions[strings.ToLower(action)]; ok {
		return append([]string{}, a.resourceTypes...)
	}
	return nil
}

// ARNFitsAction reports whether arn has the shape of one of the resource types
// the action supports, so scoping the action to it is meaningful.
func (c *Catalog) ARNFitsAction(action, arn string) bool {
	a, ok := c.actions[strings.ToLower(action)]
	if !ok {
		return false
	}
	for _, re := range a.arnPatterns {
		if re.MatchString(arn) {
			return true
		}
	}
	return false
}

// Granted returns the unique catalog actions granted by the Allow statements
// of a policy, sorted. Deny statements are ignored. An Allow statement with
// NotAction returns ErrNotAction.
func (c *Catalog) Granted(doc policy.Document) ([]string, error) {
	set := map[string]bool{}
	for _, s := range doc.Statement {
		if !strings.EqualFold(s.Effect, "Allow") {
			continue
		}
		if len(s.NotAction) > 0 {
			return nil, fmt.Errorf("statement %q: %w", s.Sid, ErrNotAction)
		}
		for _, p := range s.Action {
			for _, a := range c.Expand(p) {
				set[a] = true
			}
		}
	}
	out := make([]string, 0, len(set))
	for a := range set {
		out = append(out, a)
	}
	sort.Strings(out)
	return out, nil
}

// CountGranted is len(Granted(doc)): how many distinct actions the policy allows.
func (c *Catalog) CountGranted(doc policy.Document) (int, error) {
	g, err := c.Granted(doc)
	return len(g), err
}

// Size returns the number of actions in the catalog.
func (c *Catalog) Size() int { return len(c.all) }
