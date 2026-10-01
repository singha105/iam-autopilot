package observe

import (
	"fmt"
	"regexp"
	"strings"
)

// knownServices are the service prefixes we expect to see in event history.
// Others are still mapped (eventSource prefix as-is) but produce a warning.
var knownServices = map[string]bool{
	"cloudwatch": true, "dynamodb": true, "ec2": true, "iam": true, "kms": true,
	"lambda": true, "logs": true, "s3": true, "sns": true, "sqs": true, "ssm": true, "sts": true,
}

// sourceExceptions maps an eventSource prefix to its IAM service prefix where
// they differ.
var sourceExceptions = map[string]string{
	"monitoring": "cloudwatch",
}

// actionExceptions maps "service:EventName" to the IAM action where the
// CloudTrail event name is not the action that authorizes the call.
var actionExceptions = map[string]string{
	"s3:ListBuckets": "s3:ListAllMyBuckets",
}

// lambdaVersionSuffix matches the API version Lambda appends to event names,
// e.g. ListFunctions20150331 or UpdateFunctionConfiguration20150331v2.
var lambdaVersionSuffix = regexp.MustCompile(`[0-9]{8}(v[0-9]+)?$`)

// ServicePrefix returns the IAM service prefix for a CloudTrail eventSource
// such as "ssm.amazonaws.com". known is false for services outside
// knownServices or sources that don't end in .amazonaws.com.
func ServicePrefix(eventSource string) (prefix string, known bool) {
	prefix, ok := strings.CutSuffix(eventSource, ".amazonaws.com")
	if !ok || prefix == "" {
		return eventSource, false
	}
	if mapped, ok := sourceExceptions[prefix]; ok {
		prefix = mapped
	}
	return prefix, knownServices[prefix]
}

// ActionFor maps a CloudTrail event to the IAM action that authorized it.
// warning is non-empty when the event source is not one we know; the action
// is still returned so unknown services are kept rather than dropped.
func ActionFor(eventSource, eventName string) (action, warning string) {
	prefix, known := ServicePrefix(eventSource)
	if !known {
		warning = fmt.Sprintf("unknown event source %q: kept as %s:%s, check the IAM action name by hand", eventSource, prefix, eventName)
	}
	name := eventName
	if prefix == "lambda" {
		name = lambdaVersionSuffix.ReplaceAllString(name, "")
	}
	action = prefix + ":" + name
	if mapped, ok := actionExceptions[action]; ok {
		action = mapped
	}
	return action, warning
}

// IsDenied reports whether a CloudTrail errorCode means the call was refused
// by authorization, as opposed to failing after it was authorized.
func IsDenied(errorCode string) bool {
	return strings.Contains(errorCode, "AccessDenied") ||
		strings.Contains(errorCode, "UnauthorizedOperation") ||
		errorCode == "AuthorizationError"
}
