package observe

import (
	"context"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	"github.com/aws/aws-sdk-go-v2/service/iam"
)

// CloudTrailAPI is the subset of the CloudTrail client the observer uses.
type CloudTrailAPI interface {
	LookupEvents(context.Context, *cloudtrail.LookupEventsInput, ...func(*cloudtrail.Options)) (*cloudtrail.LookupEventsOutput, error)
}

// IAMAPI is the subset of the IAM client the observer uses.
type IAMAPI interface {
	GetRole(context.Context, *iam.GetRoleInput, ...func(*iam.Options)) (*iam.GetRoleOutput, error)
	ListRoleTags(context.Context, *iam.ListRoleTagsInput, ...func(*iam.Options)) (*iam.ListRoleTagsOutput, error)
	GenerateServiceLastAccessedDetails(context.Context, *iam.GenerateServiceLastAccessedDetailsInput, ...func(*iam.Options)) (*iam.GenerateServiceLastAccessedDetailsOutput, error)
	GetServiceLastAccessedDetails(context.Context, *iam.GetServiceLastAccessedDetailsInput, ...func(*iam.Options)) (*iam.GetServiceLastAccessedDetailsOutput, error)
}

// Tag keys that mark a role as managed by the autopilot.
const (
	TagManaged  = "autopilot:managed"
	TagFunction = "autopilot:function"
)

// Role is a target role that passed the autopilot:managed=true check.
type Role struct {
	Name         string
	ARN          string
	FunctionName string
	Tags         map[string]string
}

// Window is the observation period. Both ends are UTC, whole seconds.
type Window struct {
	Start time.Time `json:"start"`
	End   time.Time `json:"end"`
}

// ObservedCall is one (action, resource) pair the role used successfully, or
// with a non-authorization error (the call was still authorized).
type ObservedCall struct {
	Action    string    `json:"action"`
	Resource  string    `json:"resource"`
	Count     int       `json:"count"`
	FirstSeen time.Time `json:"firstSeen"`
	LastSeen  time.Time `json:"lastSeen"`
	ReadOnly  bool      `json:"readOnly"`
}

// DeniedCall is one call the role attempted and was refused.
type DeniedCall struct {
	Action    string    `json:"action"`
	Resource  string    `json:"resource"`
	ErrorCode string    `json:"errorCode"`
	Time      time.Time `json:"time"`
}

// ExcludedCall counts calls made with the role's credentials by AWS rather
// than by the function's code (ADR-002). They are not usage, but the generator
// needs them to tell when Access Advisor activity is only the platform's.
type ExcludedCall struct {
	Action string `json:"action"`
	Caller string `json:"caller"`
	Count  int    `json:"count"`
}

// ServiceAccess is one service namespace from IAM Access Advisor.
// LastAuthenticated is nil when the service was not used inside the window.
type ServiceAccess struct {
	Namespace         string          `json:"namespace"`
	LastAuthenticated *time.Time      `json:"lastAuthenticated"`
	TrackedActions    []TrackedAction `json:"trackedActions"`
}

// TrackedAction is an action-level Access Advisor entry used inside the window.
type TrackedAction struct {
	Action       string    `json:"action"`
	LastAccessed time.Time `json:"lastAccessed"`
}

// Stats counts the raw work done to build a profile.
type Stats struct {
	EventsScanned int `json:"eventsScanned"`
	PagesFetched  int `json:"pagesFetched"`
}

// Profile is the usage profile for one role: the input to policy generation.
// Field names are part of the contract with later stages; do not rename them.
type Profile struct {
	RoleARN          string          `json:"roleArn"`
	RoleName         string          `json:"roleName"`
	FunctionName     string          `json:"functionName"`
	Window           Window          `json:"window"`
	ObservedCalls    []ObservedCall  `json:"observedCalls"`
	ServicesAccessed []ServiceAccess `json:"servicesAccessed"`
	DeniedCalls      []DeniedCall    `json:"deniedCalls"`
	ExcludedCalls    []ExcludedCall  `json:"excludedCalls"`
	Warnings         []string        `json:"warnings"`
	Stats            Stats           `json:"stats"`
}
