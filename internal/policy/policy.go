// Package policy reads and writes IAM policy documents deterministically.
package policy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"unicode"
)

// Version is the only policy language version the autopilot writes.
const Version = "2012-10-17"

// Document is an IAM identity policy. Struct fields are in alphabetical order
// so that encoded keys are sorted, which keeps policy diffs in PRs clean.
type Document struct {
	Statement Statements `json:"Statement"`
	Version   string     `json:"Version"`
}

// Statement is one policy statement. Condition is kept as raw JSON so Deny
// statements can be copied through unchanged.
type Statement struct {
	Action      Strings         `json:"Action,omitempty"`
	Condition   json.RawMessage `json:"Condition,omitempty"`
	Effect      string          `json:"Effect"`
	NotAction   Strings         `json:"NotAction,omitempty"`
	NotResource Strings         `json:"NotResource,omitempty"`
	Resource    Strings         `json:"Resource,omitempty"`
	Sid         string          `json:"Sid,omitempty"`
}

// Strings is an IAM "string or array of strings" value. It always encodes as
// an array.
type Strings []string

func (s *Strings) UnmarshalJSON(b []byte) error {
	var one string
	if err := json.Unmarshal(b, &one); err == nil {
		*s = Strings{one}
		return nil
	}
	var many []string
	if err := json.Unmarshal(b, &many); err != nil {
		return fmt.Errorf("want a string or an array of strings, got %s", b)
	}
	*s = many
	return nil
}

// Statements accepts a single statement object as well as an array.
type Statements []Statement

func (s *Statements) UnmarshalJSON(b []byte) error {
	b = bytes.TrimSpace(b)
	if len(b) > 0 && b[0] == '{' {
		var one Statement
		if err := json.Unmarshal(b, &one); err != nil {
			return err
		}
		*s = Statements{one}
		return nil
	}
	var many []Statement
	if err := json.Unmarshal(b, &many); err != nil {
		return err
	}
	*s = many
	return nil
}

// Parse decodes a policy document.
func Parse(b []byte) (Document, error) {
	var d Document
	if err := json.Unmarshal(b, &d); err != nil {
		return Document{}, fmt.Errorf("parse policy: %w", err)
	}
	return d, nil
}

// Encode returns the document with 2-space indentation and a trailing newline.
func (d Document) Encode() ([]byte, error) {
	b, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// Compact returns the document as compact JSON, the form sent to AWS APIs.
func (d Document) Compact() (string, error) {
	b, err := json.Marshal(d)
	return string(b), err
}

// NonWhitespaceLen counts the characters IAM counts against the managed
// policy size limit (6,144): everything except whitespace.
func NonWhitespaceLen(b []byte) int {
	n := 0
	for _, r := range string(b) {
		if !unicode.IsSpace(r) {
			n++
		}
	}
	return n
}

// MaxManagedPolicyChars is IAM's size limit for a managed policy document.
const MaxManagedPolicyChars = 6144
