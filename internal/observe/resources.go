package observe

import (
	"fmt"
	"sort"
	"strings"
	"time"

	cttypes "github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
)

// partition is fixed: the project runs in the commercial aws partition.
const partition = "aws"

// trailEvent is the subset of a CloudTrailEvent JSON document the observer reads.
type trailEvent struct {
	EventSource        string         `json:"eventSource"`
	EventName          string         `json:"eventName"`
	EventTime          time.Time      `json:"eventTime"`
	AWSRegion          string         `json:"awsRegion"`
	RecipientAccountID string         `json:"recipientAccountId"`
	ErrorCode          string         `json:"errorCode"`
	UserAgent          string         `json:"userAgent"`
	ReadOnly           *bool          `json:"readOnly"`
	RequestParameters  map[string]any `json:"requestParameters"`
	UserIdentity       struct {
		InvokedBy      string `json:"invokedBy"`
		SessionContext struct {
			SessionIssuer struct {
				ARN string `json:"arn"`
			} `json:"sessionIssuer"`
		} `json:"sessionContext"`
	} `json:"userIdentity"`
}

// extractResources returns the ARNs a call touched, sorted and de-duplicated.
// It combines requestParameters (for ssm, dynamodb, s3 and lambda, where the
// parameter names are known) with the event's Resources list. When nothing can
// be derived the result is ["*"].
func extractResources(ev trailEvent, listed []cttypes.Resource) []string {
	region, account := ev.AWSRegion, ev.RecipientAccountID
	seen := map[string]bool{}
	add := func(arn string) {
		if arn != "" {
			seen[arn] = true
		}
	}

	prefix, _ := ServicePrefix(ev.EventSource)
	p := ev.RequestParameters
	switch prefix {
	case "ssm":
		add(ssmParameterARN(region, account, str(p, "name")))
		for _, n := range strs(p, "names") {
			add(ssmParameterARN(region, account, n))
		}
		add(ssmPathARN(region, account, str(p, "path")))
	case "dynamodb":
		add(dynamoTableARN(region, account, str(p, "tableName")))
	case "s3":
		add(s3BucketARN(str(p, "bucketName")))
	case "lambda":
		add(lambdaFunctionARN(region, account, str(p, "functionName")))
	}

	for _, r := range listed {
		add(listedResourceARN(region, account, deref(r.ResourceType), deref(r.ResourceName)))
	}

	if len(seen) == 0 {
		return []string{"*"}
	}
	out := make([]string, 0, len(seen))
	for arn := range seen {
		out = append(out, arn)
	}
	sort.Strings(out)
	return out
}

// listedResourceARN converts an entry of the event's Resources list. Names
// that are already ARNs pass through; known types are built into ARNs; other
// bare IDs (an EC2 instance ID, say) are dropped because their ARN shape is
// not known here.
func listedResourceARN(region, account, typ, name string) string {
	if strings.HasPrefix(name, "arn:") {
		return name
	}
	switch typ {
	case "AWS::SSM::Parameter":
		return ssmParameterARN(region, account, name)
	case "AWS::DynamoDB::Table":
		return dynamoTableARN(region, account, name)
	case "AWS::S3::Bucket":
		return s3BucketARN(name)
	case "AWS::Lambda::Function":
		return lambdaFunctionARN(region, account, name)
	}
	return ""
}

func ssmParameterARN(region, account, name string) string {
	if name == "" || strings.HasPrefix(name, "arn:") {
		return name
	}
	if region == "" || account == "" {
		return ""
	}
	return fmt.Sprintf("arn:%s:ssm:%s:%s:parameter/%s", partition, region, account, strings.TrimPrefix(name, "/"))
}

// ssmPathARN builds the resource IAM evaluates for GetParametersByPath: the
// path exactly as requested, trailing slash included. Verified on Day 6: a
// denial for path "/iamap/demo/quarterly/" names the resource
// parameter/iamap/demo/quarterly/ (with the slash), so dropping it would
// scope a proposal to a resource the call never matches.
func ssmPathARN(region, account, path string) string {
	if path == "" || region == "" || account == "" {
		return ""
	}
	return fmt.Sprintf("arn:%s:ssm:%s:%s:parameter/%s", partition, region, account, strings.TrimPrefix(path, "/"))
}

func dynamoTableARN(region, account, table string) string {
	if table == "" || strings.HasPrefix(table, "arn:") {
		return table
	}
	if region == "" || account == "" {
		return ""
	}
	return fmt.Sprintf("arn:%s:dynamodb:%s:%s:table/%s", partition, region, account, table)
}

func s3BucketARN(bucket string) string {
	if bucket == "" || strings.HasPrefix(bucket, "arn:") {
		return bucket
	}
	return fmt.Sprintf("arn:%s:s3:::%s", partition, bucket)
}

func lambdaFunctionARN(region, account, fn string) string {
	if fn == "" || strings.HasPrefix(fn, "arn:") {
		return fn
	}
	if region == "" || account == "" {
		return ""
	}
	return fmt.Sprintf("arn:%s:lambda:%s:%s:function:%s", partition, region, account, fn)
}

func str(m map[string]any, key string) string {
	s, _ := m[key].(string)
	return s
}

func strs(m map[string]any, key string) []string {
	raw, _ := m[key].([]any)
	out := make([]string, 0, len(raw))
	for _, v := range raw {
		if s, ok := v.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
