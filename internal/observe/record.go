package observe

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sync"

	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	"github.com/aws/aws-sdk-go-v2/service/iam"
)

// FixtureAccountID replaces the real account ID in every saved fixture.
const FixtureAccountID = "123456789012"

// fixtureAccessKeyID replaces access key IDs (temporary ASIA... or long-term
// AKIA...) that appear in CloudTrail records. They are IDs, not secrets, but
// CLAUDE.md says no keys in the repo, so none are kept.
const fixtureAccessKeyID = "ASIAIOSFODNN7EXAMPLE"

var accessKeyIDPattern = regexp.MustCompile(`\b(AKIA|ASIA)[A-Z0-9]{16}\b`)

// Redact replaces accountID with 123456789012 and access key IDs with an
// example ID. It is applied to every fixture before it is written.
func Redact(b []byte, accountID string) []byte {
	if accountID != "" && accountID != FixtureAccountID {
		b = regexp.MustCompile(regexp.QuoteMeta(accountID)).ReplaceAll(b, []byte(FixtureAccountID))
	}
	return accessKeyIDPattern.ReplaceAll(b, []byte(fixtureAccessKeyID))
}

// Recorder writes each API response to Dir as <operation>-NNN.json, numbered
// in call order, redacted. Replaying the files in order reproduces the run.
type Recorder struct {
	Dir       string
	AccountID string

	mu     sync.Mutex
	counts map[string]int
}

// Save writes v as the next fixture for op.
func (r *Recorder) Save(op string, v any) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.counts == nil {
		r.counts = map[string]int{}
	}
	r.counts[op]++
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("record %s: %w", op, err)
	}
	if err := os.MkdirAll(r.Dir, 0o755); err != nil {
		return err
	}
	name := filepath.Join(r.Dir, fmt.Sprintf("%s-%03d.json", op, r.counts[op]))
	return os.WriteFile(name, append(Redact(b, r.AccountID), '\n'), 0o644)
}

// Fixture operation names, shared by the recorder and the replaying tests.
const (
	OpLookupEvents                 = "lookup-events"
	OpGetRole                      = "get-role"
	OpListRoleTags                 = "list-role-tags"
	OpGenerateServiceLastAccessed  = "generate-service-last-accessed-details"
	OpGetServiceLastAccessedDetail = "get-service-last-accessed-details"
)

// RecordingCloudTrail saves every successful LookupEvents response.
type RecordingCloudTrail struct {
	Inner CloudTrailAPI
	Rec   *Recorder
}

func (c RecordingCloudTrail) LookupEvents(ctx context.Context, in *cloudtrail.LookupEventsInput, opts ...func(*cloudtrail.Options)) (*cloudtrail.LookupEventsOutput, error) {
	out, err := c.Inner.LookupEvents(ctx, in, opts...)
	return out, record(c.Rec, OpLookupEvents, out, err)
}

// RecordingIAM saves every successful IAM response the observer receives.
type RecordingIAM struct {
	Inner IAMAPI
	Rec   *Recorder
}

func (c RecordingIAM) GetRole(ctx context.Context, in *iam.GetRoleInput, opts ...func(*iam.Options)) (*iam.GetRoleOutput, error) {
	out, err := c.Inner.GetRole(ctx, in, opts...)
	return out, record(c.Rec, OpGetRole, out, err)
}

func (c RecordingIAM) ListRoleTags(ctx context.Context, in *iam.ListRoleTagsInput, opts ...func(*iam.Options)) (*iam.ListRoleTagsOutput, error) {
	out, err := c.Inner.ListRoleTags(ctx, in, opts...)
	return out, record(c.Rec, OpListRoleTags, out, err)
}

func (c RecordingIAM) GenerateServiceLastAccessedDetails(ctx context.Context, in *iam.GenerateServiceLastAccessedDetailsInput, opts ...func(*iam.Options)) (*iam.GenerateServiceLastAccessedDetailsOutput, error) {
	out, err := c.Inner.GenerateServiceLastAccessedDetails(ctx, in, opts...)
	return out, record(c.Rec, OpGenerateServiceLastAccessed, out, err)
}

func (c RecordingIAM) GetServiceLastAccessedDetails(ctx context.Context, in *iam.GetServiceLastAccessedDetailsInput, opts ...func(*iam.Options)) (*iam.GetServiceLastAccessedDetailsOutput, error) {
	out, err := c.Inner.GetServiceLastAccessedDetails(ctx, in, opts...)
	return out, record(c.Rec, OpGetServiceLastAccessedDetail, out, err)
}

// record saves out when the call succeeded and passes the call's error through.
func record(rec *Recorder, op string, out any, err error) error {
	if err != nil {
		return err
	}
	return rec.Save(op, out)
}
