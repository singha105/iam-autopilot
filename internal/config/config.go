// Package config loads autopilot.yaml.
package config

import (
	"context"
	"fmt"
	"os"
	"path"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// DefaultPath is where the CLI looks for the config.
const DefaultPath = "autopilot.yaml"

// Config is the parsed autopilot.yaml.
type Config struct {
	GitHub           GitHub              `yaml:"github"`
	Roles            []Role              `yaml:"roles"`
	NeverRemove      []KeepEntry         `yaml:"neverRemove"`
	DataPlaneActions map[string][]string `yaml:"dataPlaneActions"`
	Watch            Watch               `yaml:"watch"`
}

// GitHub names the repository that holds the policy files and this config.
type GitHub struct {
	Owner  string `yaml:"owner"`
	Repo   string `yaml:"repo"`
	Branch string `yaml:"branch"`
}

// Role is one role the autopilot may tighten.
type Role struct {
	Name string `yaml:"name"`
	// PolicyFile is the repo path of the role's managed policy JSON, the file
	// a proposal PR edits (e.g. policies/demo/inventory.json).
	PolicyFile      string      `yaml:"policyFile"`
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

// Load reads and validates a local config file (the CLI's source).
func Load(path string) (Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}
	return Parse(b)
}

// FileFetcher reads a file from a repository at a ref. githubpr.Client
// implements it with the GitHub contents API.
type FileFetcher interface {
	FetchFile(ctx context.Context, path, ref string) ([]byte, error)
}

// LoadFrom reads and validates the config from a repository (the Lambda's
// source on Day 5: autopilot.yaml on main). Same struct, same validation.
func LoadFrom(ctx context.Context, f FileFetcher, path, ref string) (Config, error) {
	b, err := f.FetchFile(ctx, path, ref)
	if err != nil {
		return Config{}, fmt.Errorf("config: fetch %s@%s: %w", path, ref, err)
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
	if c.GitHub.Owner == "" {
		c.GitHub.Owner = "singha105"
	}
	if c.GitHub.Repo == "" {
		c.GitHub.Repo = "iam-autopilot"
	}
	if c.GitHub.Branch == "" {
		c.GitHub.Branch = "main"
	}
	return c, c.validate()
}

func (c Config) validate() error {
	if c.Watch.Minutes <= 0 || c.Watch.LagBufferMinutes <= 0 || c.Watch.PollSeconds <= 0 {
		return fmt.Errorf("config: watch.minutes, watch.lagBufferMinutes and watch.pollSeconds must all be > 0 (got %d, %d, %d)",
			c.Watch.Minutes, c.Watch.LagBufferMinutes, c.Watch.PollSeconds)
	}
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
		if r.PolicyFile != "" && (path.Clean(r.PolicyFile) != r.PolicyFile || !strings.HasPrefix(r.PolicyFile, "policies/") || !strings.HasSuffix(r.PolicyFile, ".json")) {
			return fmt.Errorf("config: role %s: policyFile %q must be a clean path under policies/ ending in .json", r.Name, r.PolicyFile)
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

// RoleOrError returns the config for a role, or an error naming the file: a
// role the config does not list is never touched.
func (c Config) RoleOrError(name string) (Role, error) {
	if r, ok := c.Role(name); ok {
		return r, nil
	}
	return Role{}, fmt.Errorf("config: role %s is not listed in autopilot.yaml", name)
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
