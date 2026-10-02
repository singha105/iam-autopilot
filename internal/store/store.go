package store

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	ddbtypes "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

// DefaultTable is the Terraform-managed rollouts table.
const DefaultTable = "iamap-rollouts"

// Status is a rollout's state.
type Status string

const (
	StatusObserving        Status = "OBSERVING"
	StatusShadowFailed     Status = "SHADOW_FAILED"
	StatusNothingToDo      Status = "NOTHING_TO_DO"
	StatusPROpen           Status = "PR_OPEN"
	StatusApproved         Status = "APPROVED"
	StatusCancelled        Status = "CANCELLED"
	StatusEnforcedWatching Status = "ENFORCED_WATCHING"
	StatusEnforced         Status = "ENFORCED"
	StatusRolledBack       Status = "ROLLED_BACK"
	StatusFailed           Status = "FAILED"
)

// Final reports whether no further transition is expected from s.
func (s Status) Final() bool {
	switch s {
	case StatusShadowFailed, StatusNothingToDo, StatusCancelled, StatusEnforced, StatusRolledBack, StatusFailed:
		return true
	}
	return false
}

// maxPayloadBytes keeps items far below DynamoDB's 400 KB item limit.
const maxPayloadBytes = 300 * 1024

var (
	// ErrConflict means the rollout was not in the expected status: another
	// process moved it first.
	ErrConflict = errors.New("rollout status changed concurrently")
	// ErrNotFound means no rollout has that ID.
	ErrNotFound = errors.New("rollout not found")
	// ErrTooLarge means proposedPolicy+summary+shadowReport exceed 300 KB.
	ErrTooLarge = errors.New("rollout payload too large")
	// ErrExists means a rollout with that ID already exists.
	ErrExists = errors.New("rollout already exists")
)

// Metrics are the numbers a rollout reports.
type Metrics struct {
	GrantedBefore   int      `dynamodbav:"grantedBefore" json:"grantedBefore"`
	GrantedAfter    int      `dynamodbav:"grantedAfter" json:"grantedAfter"`
	RemovedPercent  float64  `dynamodbav:"removedPercent" json:"removedPercent"`
	ObservedActions int      `dynamodbav:"observedActions" json:"observedActions"`
	ShadowTested    int      `dynamodbav:"shadowTested" json:"shadowTested"`
	ShadowDenied    int      `dynamodbav:"shadowDenied" json:"shadowDenied"`
	DetectSeconds   float64  `dynamodbav:"detectSeconds" json:"detectSeconds"`
	RollbackSeconds float64  `dynamodbav:"rollbackSeconds" json:"rollbackSeconds"`
	DeniedActions   []string `dynamodbav:"deniedActions" json:"deniedActions"`
}

// Rollout is one attempt to tighten one role's policy. Attribute names are
// the DynamoDB item's; timestamps are RFC3339 strings.
type Rollout struct {
	RolloutID        string  `dynamodbav:"rolloutId" json:"rolloutId"`
	RoleName         string  `dynamodbav:"roleName" json:"roleName"`
	RoleArn          string  `dynamodbav:"roleArn" json:"roleArn"`
	FunctionName     string  `dynamodbav:"functionName" json:"functionName"`
	PolicyArn        string  `dynamodbav:"policyArn" json:"policyArn"`
	Status           Status  `dynamodbav:"status" json:"status"`
	CurrentVersionID string  `dynamodbav:"currentVersionId,omitempty" json:"currentVersionId,omitempty"`
	ProposedPolicy   string  `dynamodbav:"proposedPolicy,omitempty" json:"proposedPolicy,omitempty"`
	Summary          string  `dynamodbav:"summary,omitempty" json:"summary,omitempty"`
	ShadowReport     string  `dynamodbav:"shadowReport,omitempty" json:"shadowReport,omitempty"`
	PRNumber         int     `dynamodbav:"prNumber,omitempty" json:"prNumber,omitempty"`
	PRURL            string  `dynamodbav:"prUrl,omitempty" json:"prUrl,omitempty"`
	PRBranch         string  `dynamodbav:"prBranch,omitempty" json:"prBranch,omitempty"`
	TaskToken        string  `dynamodbav:"taskToken,omitempty" json:"taskToken,omitempty"`
	PrevVersionID    string  `dynamodbav:"prevVersionId,omitempty" json:"prevVersionId,omitempty"`
	NewVersionID     string  `dynamodbav:"newVersionId,omitempty" json:"newVersionId,omitempty"`
	CreatedAt        string  `dynamodbav:"createdAt" json:"createdAt"`
	ApprovedAt       string  `dynamodbav:"approvedAt,omitempty" json:"approvedAt,omitempty"`
	EnforcedAt       string  `dynamodbav:"enforcedAt,omitempty" json:"enforcedAt,omitempty"`
	DetectedAt       string  `dynamodbav:"detectedAt,omitempty" json:"detectedAt,omitempty"`
	RolledBackAt     string  `dynamodbav:"rolledBackAt,omitempty" json:"rolledBackAt,omitempty"`
	FinishedAt       string  `dynamodbav:"finishedAt,omitempty" json:"finishedAt,omitempty"`
	Metrics          Metrics `dynamodbav:"metrics" json:"metrics"`
}

// NewID returns "<roleName>-<UTC yyyymmddThhmmssZ>".
func NewID(roleName string, t time.Time) string {
	return roleName + "-" + t.UTC().Format("20060102T150405Z")
}

// Timestamp formats t the way every *At field is stored.
func Timestamp(t time.Time) string { return t.UTC().Format(time.RFC3339) }

// API is the subset of the DynamoDB client the store uses.
type API interface {
	PutItem(context.Context, *dynamodb.PutItemInput, ...func(*dynamodb.Options)) (*dynamodb.PutItemOutput, error)
	GetItem(context.Context, *dynamodb.GetItemInput, ...func(*dynamodb.Options)) (*dynamodb.GetItemOutput, error)
	UpdateItem(context.Context, *dynamodb.UpdateItemInput, ...func(*dynamodb.Options)) (*dynamodb.UpdateItemOutput, error)
	Scan(context.Context, *dynamodb.ScanInput, ...func(*dynamodb.Options)) (*dynamodb.ScanOutput, error)
}

// Store reads and writes rollout records.
type Store struct {
	DB    API
	Table string
}

// New returns a Store for the given table (DefaultTable if empty).
func New(db API, table string) *Store {
	if table == "" {
		table = DefaultTable
	}
	return &Store{DB: db, Table: table}
}

func checkSize(r Rollout) error {
	if n := len(r.ProposedPolicy) + len(r.Summary) + len(r.ShadowReport); n > maxPayloadBytes {
		return fmt.Errorf("%w: proposedPolicy+summary+shadowReport is %d bytes (limit %d)", ErrTooLarge, n, maxPayloadBytes)
	}
	return nil
}

// Create writes a new rollout; it fails if the ID already exists.
func (s *Store) Create(ctx context.Context, r Rollout) error {
	if r.RolloutID == "" || r.RoleName == "" || r.Status == "" || r.CreatedAt == "" {
		return errors.New("rollout needs rolloutId, roleName, status and createdAt")
	}
	if err := checkSize(r); err != nil {
		return err
	}
	item, err := attributevalue.MarshalMap(r)
	if err != nil {
		return fmt.Errorf("marshal rollout: %w", err)
	}
	_, err = s.DB.PutItem(ctx, &dynamodb.PutItemInput{
		TableName:           aws.String(s.Table),
		Item:                item,
		ConditionExpression: aws.String("attribute_not_exists(rolloutId)"),
	})
	if isConditionFailed(err) {
		return fmt.Errorf("%w: %s", ErrExists, r.RolloutID)
	}
	if err != nil {
		return fmt.Errorf("create rollout %s: %w", r.RolloutID, err)
	}
	return nil
}

// Get reads one rollout with a strongly consistent read.
func (s *Store) Get(ctx context.Context, id string) (Rollout, error) {
	out, err := s.DB.GetItem(ctx, &dynamodb.GetItemInput{
		TableName:      aws.String(s.Table),
		Key:            key(id),
		ConsistentRead: aws.Bool(true),
	})
	if err != nil {
		return Rollout{}, fmt.Errorf("get rollout %s: %w", id, err)
	}
	if len(out.Item) == 0 {
		return Rollout{}, fmt.Errorf("%w: %s", ErrNotFound, id)
	}
	var r Rollout
	if err := attributevalue.UnmarshalMap(out.Item, &r); err != nil {
		return Rollout{}, fmt.Errorf("unmarshal rollout %s: %w", id, err)
	}
	return r, nil
}

// UpdateStatus moves a rollout from one status to another, only if it is
// still in `from`. ErrConflict means another process got there first.
func (s *Store) UpdateStatus(ctx context.Context, id string, from, to Status) error {
	_, err := s.DB.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName:                aws.String(s.Table),
		Key:                      key(id),
		UpdateExpression:         aws.String("SET #status = :to"),
		ConditionExpression:      aws.String("#status = :from"),
		ExpressionAttributeNames: map[string]string{"#status": "status"},
		ExpressionAttributeValues: map[string]ddbtypes.AttributeValue{
			":from": &ddbtypes.AttributeValueMemberS{Value: string(from)},
			":to":   &ddbtypes.AttributeValueMemberS{Value: string(to)},
		},
	})
	if isConditionFailed(err) {
		return fmt.Errorf("%w: %s is no longer %s (wanted to move it to %s)", ErrConflict, id, from, to)
	}
	if err != nil {
		return fmt.Errorf("update status of %s: %w", id, err)
	}
	return nil
}

// settable lists the attributes SetFields may write. Keys and status are
// excluded: status only moves through UpdateStatus.
var settable = map[string]bool{
	"roleArn": true, "functionName": true, "policyArn": true, "currentVersionId": true,
	"proposedPolicy": true, "summary": true, "shadowReport": true,
	"prNumber": true, "prUrl": true, "prBranch": true, "taskToken": true,
	"prevVersionId": true, "newVersionId": true,
	"approvedAt": true, "enforcedAt": true, "detectedAt": true, "rolledBackAt": true, "finishedAt": true,
	"metrics": true,
}

// SetFields sets attributes on an existing rollout. Unknown attribute names
// are rejected so a typo cannot create a stray attribute.
func (s *Store) SetFields(ctx context.Context, id string, fields map[string]any) error {
	if len(fields) == 0 {
		return nil
	}
	names := make([]string, 0, len(fields))
	for name := range fields {
		if !settable[name] {
			return fmt.Errorf("SetFields: %q is not a settable rollout attribute", name)
		}
		names = append(names, name)
	}
	sort.Strings(names)

	payload := 0
	for _, f := range []string{"proposedPolicy", "summary", "shadowReport"} {
		if v, ok := fields[f].(string); ok {
			payload += len(v)
		}
	}
	if payload > maxPayloadBytes {
		return fmt.Errorf("%w: %d bytes (limit %d)", ErrTooLarge, payload, maxPayloadBytes)
	}

	attrNames := map[string]string{}
	attrValues := map[string]ddbtypes.AttributeValue{}
	sets := make([]string, 0, len(names))
	for i, name := range names {
		v, err := attributevalue.Marshal(fields[name])
		if err != nil {
			return fmt.Errorf("marshal %s: %w", name, err)
		}
		n, val := fmt.Sprintf("#f%d", i), fmt.Sprintf(":v%d", i)
		attrNames[n] = name
		attrValues[val] = v
		sets = append(sets, n+" = "+val)
	}
	_, err := s.DB.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName:                 aws.String(s.Table),
		Key:                       key(id),
		UpdateExpression:          aws.String("SET " + strings.Join(sets, ", ")),
		ConditionExpression:       aws.String("attribute_exists(rolloutId)"),
		ExpressionAttributeNames:  attrNames,
		ExpressionAttributeValues: attrValues,
	})
	if isConditionFailed(err) {
		return fmt.Errorf("%w: %s", ErrNotFound, id)
	}
	if err != nil {
		return fmt.Errorf("set fields on %s: %w", id, err)
	}
	return nil
}

// ListAll scans every rollout, newest first. A scan is fine at this size.
func (s *Store) ListAll(ctx context.Context) ([]Rollout, error) {
	return s.scan(ctx, nil)
}

// ActiveForRole returns the role's rollouts that are not in a final state.
// The CLI refuses to start a second rollout while one is active.
func (s *Store) ActiveForRole(ctx context.Context, roleName string) ([]Rollout, error) {
	all, err := s.scan(ctx, &roleName)
	if err != nil {
		return nil, err
	}
	var active []Rollout
	for _, r := range all {
		if !r.Status.Final() {
			active = append(active, r)
		}
	}
	return active, nil
}

func (s *Store) scan(ctx context.Context, roleName *string) ([]Rollout, error) {
	in := &dynamodb.ScanInput{TableName: aws.String(s.Table)}
	if roleName != nil {
		in.FilterExpression = aws.String("roleName = :r")
		in.ExpressionAttributeValues = map[string]ddbtypes.AttributeValue{":r": &ddbtypes.AttributeValueMemberS{Value: *roleName}}
	}
	var out []Rollout
	for {
		page, err := s.DB.Scan(ctx, in)
		if err != nil {
			return nil, fmt.Errorf("scan rollouts: %w", err)
		}
		for _, item := range page.Items {
			var r Rollout
			if err := attributevalue.UnmarshalMap(item, &r); err != nil {
				return nil, fmt.Errorf("unmarshal rollout: %w", err)
			}
			out = append(out, r)
		}
		if len(page.LastEvaluatedKey) == 0 {
			break
		}
		in.ExclusiveStartKey = page.LastEvaluatedKey
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].CreatedAt != out[j].CreatedAt {
			return out[i].CreatedAt > out[j].CreatedAt
		}
		return out[i].RolloutID > out[j].RolloutID
	})
	return out, nil
}

func key(id string) map[string]ddbtypes.AttributeValue {
	return map[string]ddbtypes.AttributeValue{"rolloutId": &ddbtypes.AttributeValueMemberS{Value: id}}
}

func isConditionFailed(err error) bool {
	var ccf *ddbtypes.ConditionalCheckFailedException
	return errors.As(err, &ccf)
}
