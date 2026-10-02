package config

import (
	"bytes"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

var (
	roleLine = regexp.MustCompile(`^(\s*)- name:\s*(\S+)\s*$`)
	keepLine = regexp.MustCompile(`^(\s+)keepActions:\s*\[(.*)\]\s*(#.*)?$`)
)

// AddKeepActions returns autopilot.yaml with actions added to the role's
// keepActions (de-duplicated, sorted). It edits only that role's
// `keepActions: [...]` line, so a revert PR shows a one-line diff and every
// comment and blank line survives; if the line is not in that flow form it
// falls back to a structured YAML edit. The result is re-validated.
func AddKeepActions(src []byte, role string, actions []string) ([]byte, error) {
	out, ok := addKeepActionsInLine(src, role, actions)
	if !ok {
		var err error
		if out, err = addKeepActionsNode(src, role, actions); err != nil {
			return nil, err
		}
	}
	c, err := Parse(out)
	if err != nil {
		return nil, fmt.Errorf("edited config is invalid: %w", err)
	}
	r, err := c.RoleOrError(role)
	if err != nil {
		return nil, err
	}
	have := map[string]bool{}
	for _, k := range r.KeepActions {
		have[k.Action] = true
	}
	for _, a := range actions {
		if !have[a] {
			return nil, fmt.Errorf("edited config does not keep %s for %s", a, role)
		}
	}
	return out, nil
}

func addKeepActionsInLine(src []byte, role string, actions []string) ([]byte, bool) {
	lines := strings.Split(string(src), "\n")
	in := false
	for i, line := range lines {
		if m := roleLine.FindStringSubmatch(line); m != nil {
			in = m[2] == role
			continue
		}
		if !in {
			continue
		}
		m := keepLine.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		if strings.Contains(m[2], "{") {
			return nil, false // {action, resource} entries: use the structured edit
		}
		set := map[string]bool{}
		for _, item := range strings.Split(m[2], ",") {
			if item = strings.TrimSpace(item); item != "" {
				set[item] = true
			}
		}
		for _, a := range actions {
			set[a] = true
		}
		items := make([]string, 0, len(set))
		for a := range set {
			items = append(items, a)
		}
		sort.Strings(items)
		comment := ""
		if m[3] != "" {
			comment = " " + m[3]
		}
		lines[i] = m[1] + "keepActions: [" + strings.Join(items, ", ") + "]" + comment
		return []byte(strings.Join(lines, "\n")), true
	}
	return nil, false
}

func addKeepActionsNode(src []byte, role string, actions []string) ([]byte, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal(src, &doc); err != nil || len(doc.Content) == 0 {
		return nil, fmt.Errorf("parse config: %v", err)
	}
	roles := mapValue(doc.Content[0], "roles")
	if roles == nil || roles.Kind != yaml.SequenceNode {
		return nil, fmt.Errorf("config has no roles list")
	}
	for _, r := range roles.Content {
		if name := mapValue(r, "name"); name == nil || name.Value != role {
			continue
		}
		keep := mapValue(r, "keepActions")
		if keep == nil {
			keep = &yaml.Node{Kind: yaml.SequenceNode, Style: yaml.FlowStyle}
			r.Content = append(r.Content, &yaml.Node{Kind: yaml.ScalarNode, Value: "keepActions"}, keep)
		}
		have := map[string]bool{}
		for _, n := range keep.Content {
			if n.Kind == yaml.ScalarNode {
				have[n.Value] = true
			} else if a := mapValue(n, "action"); a != nil {
				have[a.Value] = true
			}
		}
		sorted := append([]string{}, actions...)
		sort.Strings(sorted)
		for _, a := range sorted {
			if !have[a] {
				keep.Content = append(keep.Content, &yaml.Node{Kind: yaml.ScalarNode, Value: a})
				have[a] = true
			}
		}
		var buf bytes.Buffer
		enc := yaml.NewEncoder(&buf)
		enc.SetIndent(2)
		if err := enc.Encode(&doc); err != nil {
			return nil, err
		}
		return buf.Bytes(), nil
	}
	return nil, fmt.Errorf("config: role %s is not listed in autopilot.yaml", role)
}

func mapValue(m *yaml.Node, key string) *yaml.Node {
	if m == nil || m.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return m.Content[i+1]
		}
	}
	return nil
}
