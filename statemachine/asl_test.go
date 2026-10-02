// Package statemachine holds the rollout workflow definition (rollout.asl.json,
// deployed by Terraform with templatefile) and tests that check its structure.
package statemachine

import (
	"encoding/json"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"
)

type state struct {
	Type           string          `json:"Type"`
	Resource       string          `json:"Resource"`
	Next           string          `json:"Next"`
	Default        string          `json:"Default"`
	Choices        []choice        `json:"Choices"`
	Catch          []catcher       `json:"Catch"`
	Retry          []retrier       `json:"Retry"`
	Parameters     json.RawMessage `json:"Parameters"`
	TimeoutSeconds int             `json:"TimeoutSeconds"`
	SecondsPath    string          `json:"SecondsPath"`
	Error          string          `json:"Error"`
}

type choice struct {
	Variable string `json:"Variable"`
	Next     string `json:"Next"`
}

type catcher struct {
	ErrorEquals []string `json:"ErrorEquals"`
	Next        string   `json:"Next"`
}

type retrier struct {
	ErrorEquals []string `json:"ErrorEquals"`
	MaxAttempts int      `json:"MaxAttempts"`
	BackoffRate float64  `json:"BackoffRate"`
}

type machine struct {
	StartAt string           `json:"StartAt"`
	States  map[string]state `json:"States"`
}

func load(t *testing.T) machine {
	t.Helper()
	raw, err := os.ReadFile("rollout.asl.json")
	if err != nil {
		t.Fatal(err)
	}
	// Terraform's templatefile fills ${worker_arn}; nothing else may use ${.
	if strings.Count(string(raw), "${") != strings.Count(string(raw), "${worker_arn}") {
		t.Fatal("only ${worker_arn} may be templated")
	}
	js := strings.ReplaceAll(string(raw), "${worker_arn}", "arn:aws:lambda:us-east-1:123456789012:function:iamap-worker")
	var m machine
	dec := json.NewDecoder(strings.NewReader(js))
	if err := dec.Decode(&m); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestStructure(t *testing.T) {
	m := load(t)
	if _, ok := m.States[m.StartAt]; !ok {
		t.Fatalf("StartAt %s missing", m.StartAt)
	}
	reached := map[string]bool{m.StartAt: true}
	for name, s := range m.States {
		targets := []string{s.Next, s.Default}
		for _, c := range s.Choices {
			targets = append(targets, c.Next)
		}
		for _, c := range s.Catch {
			targets = append(targets, c.Next)
		}
		for _, n := range targets {
			if n == "" {
				continue
			}
			if _, ok := m.States[n]; !ok {
				t.Errorf("%s points at missing state %s", name, n)
			}
			reached[n] = true
		}
		switch s.Type {
		case "Task":
			if len(s.Retry) == 0 || s.Retry[0].MaxAttempts != 3 || s.Retry[0].BackoffRate != 2 ||
				!reflect.DeepEqual(s.Retry[0].ErrorEquals, []string{"Lambda.ServiceException", "Lambda.TooManyRequestsException", "Lambda.SdkClientException"}) {
				t.Errorf("%s: Retry = %+v", name, s.Retry)
			}
			if !strings.Contains(string(s.Parameters), "function:iamap-worker") {
				t.Errorf("%s does not invoke iamap-worker", name)
			}
		case "Succeed", "Fail":
			if s.Next != "" {
				t.Errorf("terminal %s has Next", name)
			}
		default:
			if s.Next == "" && s.Default == "" {
				t.Errorf("%s has no way out", name)
			}
		}
	}
	for name := range m.States {
		if !reached[name] {
			t.Errorf("state %s is unreachable", name)
		}
	}

	aw := m.States["AwaitApproval"]
	if aw.Resource != "arn:aws:states:::lambda:invoke.waitForTaskToken" || aw.TimeoutSeconds != 604800 ||
		!strings.Contains(string(aw.Parameters), `"taskToken.$": "$$.Task.Token"`) {
		t.Errorf("AwaitApproval = %+v", aw)
	}
	cancelled := false
	for _, c := range aw.Catch {
		if reflect.DeepEqual(c.ErrorEquals, []string{"States.Timeout", "PRClosed"}) && c.Next == "Cancel" {
			cancelled = true
		}
	}
	if !cancelled {
		t.Error("States.Timeout and PRClosed must lead to Cancel")
	}
	if m.States["ObserveGenerateShadow"].Catch[0].Next != "MarkFailed" {
		t.Error("ObserveGenerateShadow must catch into MarkFailed")
	}
	if m.States["WaitBeforeWatch"].SecondsPath != "$.pollSeconds" {
		t.Error("the watch interval comes from config pollSeconds")
	}
	if m.States["RolledBack"].Type != "Fail" || m.States["RolledBack"].Error != "RolledBack" {
		t.Error("a rollback must end red with Error RolledBack")
	}
}

// walk follows the normal path and counts the states entered (each is one
// billable state transition in a STANDARD workflow).
func walk(t *testing.T, m machine, decide func(name string) string, limit int) []string {
	t.Helper()
	var path []string
	cur := m.StartAt
	for cur != "" && len(path) < limit {
		path = append(path, cur)
		s := m.States[cur]
		switch s.Type {
		case "Succeed", "Fail":
			return path
		case "Choice":
			cur = decide(cur)
		default:
			cur = s.Next
		}
	}
	t.Fatalf("no terminal state within %d steps: %v", limit, path)
	return nil
}

// TestTransitionsForOneNormalRollout: watch.minutes 30 + lagBufferMinutes 15
// with pollSeconds 300 means 9 watch iterations before Done.
func TestTransitionsForOneNormalRollout(t *testing.T) {
	m := load(t)
	iterations := (30 + 15) * 60 / 300
	watched := 0
	path := walk(t, m, func(name string) string {
		switch name {
		case "Decide":
			return m.States[name].Default // Propose
		case "CheckWatch":
			watched++
			if watched == iterations {
				return "Complete"
			}
			return m.States[name].Default // WaitBeforeWatch
		}
		t.Fatalf("unexpected choice %s", name)
		return ""
	}, 200)
	if path[len(path)-1] != "Done" {
		t.Fatalf("normal rollout ended in %s", path[len(path)-1])
	}
	// 6 states up to Enforce, 3 per watch iteration, Complete and Done.
	if want := 6 + 3*iterations + 2; len(path) != want || len(path) != 35 {
		t.Errorf("transitions = %d, want %d (keep README and DECISIONS in sync)", len(path), want)
	}
	// Free tier: 4,000 transitions a month, about 114 normal rollouts.
	if 4000/len(path) < 100 {
		t.Errorf("a rollout uses too much of the free tier")
	}
}

func TestEveryTerminalIsReachableByAScenario(t *testing.T) {
	m := load(t)
	ends := map[string]bool{}
	scenarios := map[string]map[string]string{
		"shadow failed": {"Decide": "ShadowFailed"},
		"nothing to do": {"Decide": "NothingToDo"},
		"rolled back":   {"Decide": "Propose", "CheckWatch": "Rollback"},
	}
	for _, choices := range scenarios {
		path := walk(t, m, func(n string) string { return choices[n] }, 50)
		ends[path[len(path)-1]] = true
	}
	var got []string
	for e := range ends {
		got = append(got, e)
	}
	sort.Strings(got)
	if !reflect.DeepEqual(got, []string{"NothingToDo", "RolledBack", "ShadowFailed"}) {
		t.Errorf("terminal states reached = %v", got)
	}
}
