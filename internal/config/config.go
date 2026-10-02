// Package config loads autopilot.yaml.
package config

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// DefaultPath is where the CLI looks for the config.
const DefaultPath = "autopilot.yaml"

// Config is the parsed autopilot.yaml.
type Config struct {
	Roles            []Role              `yaml:"roles"`
	NeverRemove      []KeepEntry         `yaml:"neverRemove"`
	DataPlaneActions map[string][]string `yaml:"dataPlaneActions"`
	Watch            Watch               `yaml:"watch"`
}

// Role is one role the autopilot may tighten.
type Role struct {
	Name            string      `yaml:"name"`
	ObservationDays int         `yaml:"observationDays"`
	KeepActions     []KeepEntry `yaml:"keepActions"`
	// DataPlaneActions overrides the global list per service for this role,
	// for when the owner knows which unobservable calls the code makes.
	DataPlaneActions map[string][]string `yaml:"dataPlaneActions"`
}

// KeepEntry is an action that must never be removed. In YAML it is either a
// plain string ("ssm:GetParametersByPath") or a mapping with an optional
// resource ({action: ..., resource: arn:...}). Resource defaults to "*".
type KeepEntry struct {
	Action   string `yaml:"action"`
	Resource string `yaml:"resource"`
}

func (k *KeepEntry) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind == yaml.ScalarNode {
		k.Action = n.Value
		return nil
	}
	type plain KeepEntry
	return n.Decode((*plain)(k))
}

// ResourceOrStar returns the configured resource, or "*" if none was given.
func (k KeepEntry) ResourceOrStar() string {
	if k.Resource == "" {
		return "*"
	}
	return k.Resource
}

// Watch is the post-apply watch window.
type Watch struct {
	Minutes          int `yaml:"minutes"`
	LagBufferMinutes int `yaml:"lagBufferMinutes"`
	PollSeconds      int `yaml:"pollSeconds"`
}

// Load reads and validates a config file.
func Load(path string) (Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}
	return Parse(b)
}

// Parse decodes and validates config YAML. Unknown fields are errors so typos
// in a keep-list cannot silently drop a protection.
func Parse(b []byte) (Config, error) {
	var c Config
	dec := yaml.NewDecoder(strings.NewReader(string(b)))
	dec.KnownFields(true)
	if err := dec.Decode(&c); err != nil {
		return Config{}, fmt.Errorf("config: %w", err)
	}
	return c, c.validate()
}

func (c Config) validate() error {
	seen := map[string]bool{}
	for _, r := range c.Roles {
		if r.Name == "" {
			return fmt.Errorf("config: a role has no name")
		}
		if seen[r.Name] {
			return fmt.Errorf("config: role %s listed twice", r.Name)
		}
		seen[r.Name] = true
		if r.ObservationDays < 0 || r.ObservationDays > 90 {
			return fmt.Errorf("config: role %s: observationDays must be 1-90 (event history keeps 90 days)", r.Name)
		}
		for _, k := range r.KeepActions {
			if err := k.validate(); err != nil {
				return fmt.Errorf("config: role %s keepActions: %w", r.Name, err)
			}
		}
	}
	for _, k := range c.NeverRemove {
		if err := k.validate(); err != nil {
			return fmt.Errorf("config: neverRemove: %w", err)
		}
	}
	return nil
}

func (k KeepEntry) validate() error {
	if !strings.Contains(k.Action, ":") {
		return fmt.Errorf("%q is not a service:Action name", k.Action)
	}
	return nil
}

// Role returns the config for a role name.
func (c Config) Role(name string) (Role, bool) {
	for _, r := range c.Roles {
		if r.Name == name {
			return r, true
		}
	}
	return Role{}, false
}

// DataPlane returns the global data-plane actions of a service as full
// "service:Action" names, sorted.
func (c Config) DataPlane(service string) []string {
	return qualify(service, c.DataPlaneActions[service])
}

// DataPlaneFor returns the role's data-plane actions for a service: the role's
// override if it lists that service, otherwise the global list.
func (c Config) DataPlaneFor(role, service string) []string {
	if r, ok := c.Role(role); ok {
		if actions, ok := r.DataPlaneActions[service]; ok {
			return qualify(service, actions)
		}
	}
	return c.DataPlane(service)
}

func qualify(service string, actions []string) []string {
	out := []string{}
	for _, a := range actions {
		out = append(out, service+":"+a)
	}
	sort.Strings(out)
	return out
}
