package observe

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	cttypes "github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
)

func event(t *testing.T, source, name, params string) trailEvent {
	t.Helper()
	var ev trailEvent
	doc := `{"eventSource":"` + source + `","eventName":"` + name + `","awsRegion":"us-east-1","recipientAccountId":"123456789012","requestParameters":` + params + `}`
	if err := json.Unmarshal([]byte(doc), &ev); err != nil {
		t.Fatal(err)
	}
	return ev
}

func TestExtractResources(t *testing.T) {
	tests := []struct {
		name   string
		ev     trailEvent
		listed []cttypes.Resource
		want   []string
	}{
		{
			name: "ssm GetParameter name with leading slash",
			ev:   event(t, "ssm.amazonaws.com", "GetParameter", `{"name":"/iamap/demo/config","withDecryption":false}`),
			want: []string{"arn:aws:ssm:us-east-1:123456789012:parameter/iamap/demo/config"},
		},
		{
			name: "ssm GetParameter name without slash",
			ev:   event(t, "ssm.amazonaws.com", "GetParameter", `{"name":"plain"}`),
			want: []string{"arn:aws:ssm:us-east-1:123456789012:parameter/plain"},
		},
		{
			name: "ssm GetParameters names list",
			ev:   event(t, "ssm.amazonaws.com", "GetParameters", `{"names":["/b","/a"]}`),
			want: []string{"arn:aws:ssm:us-east-1:123456789012:parameter/a", "arn:aws:ssm:us-east-1:123456789012:parameter/b"},
		},
		{
			name: "ssm GetParametersByPath keeps the trailing slash IAM evaluates",
			ev:   event(t, "ssm.amazonaws.com", "GetParametersByPath", `{"path":"/iamap/demo/quarterly/","recursive":false}`),
			want: []string{"arn:aws:ssm:us-east-1:123456789012:parameter/iamap/demo/quarterly/"},
		},
		{
			name: "dynamodb tableName",
			ev:   event(t, "dynamodb.amazonaws.com", "DescribeTable", `{"tableName":"iamap-demo-config"}`),
			want: []string{"arn:aws:dynamodb:us-east-1:123456789012:table/iamap-demo-config"},
		},
		{
			name: "dynamodb tableName given as an ARN",
			ev:   event(t, "dynamodb.amazonaws.com", "DescribeTable", `{"tableName":"arn:aws:dynamodb:eu-west-1:123456789012:table/t"}`),
			want: []string{"arn:aws:dynamodb:eu-west-1:123456789012:table/t"},
		},
		{
			name: "s3 bucketName has no region or account",
			ev:   event(t, "s3.amazonaws.com", "GetBucketLocation", `{"bucketName":"my-bucket","location":""}`),
			want: []string{"arn:aws:s3:::my-bucket"},
		},
		{
			name: "lambda functionName",
			ev:   event(t, "lambda.amazonaws.com", "GetFunction20150331v2", `{"functionName":"iamap-demo-inventory"}`),
			want: []string{"arn:aws:lambda:us-east-1:123456789012:function:iamap-demo-inventory"},
		},
		{
			name: "list calls have no resource",
			ev:   event(t, "iam.amazonaws.com", "ListRoles", `{"maxItems":5}`),
			want: []string{"*"},
		},
		{
			name: "null requestParameters",
			ev:   event(t, "s3.amazonaws.com", "ListBuckets", `null`),
			want: []string{"*"},
		},
		{
			name: "Resources list: ARN kept, known type built, bare ID dropped, duplicates merged",
			ev:   event(t, "ssm.amazonaws.com", "GetParameter", `{"name":"/iamap/demo/config"}`),
			listed: []cttypes.Resource{
				{ResourceType: aws.String("AWS::SSM::Parameter"), ResourceName: aws.String("/iamap/demo/config")},
				{ResourceType: aws.String("AWS::KMS::Key"), ResourceName: aws.String("arn:aws:kms:us-east-1:123456789012:key/abc")},
				{ResourceType: aws.String("AWS::EC2::Instance"), ResourceName: aws.String("i-0123456789abcdef0")},
			},
			want: []string{
				"arn:aws:kms:us-east-1:123456789012:key/abc",
				"arn:aws:ssm:us-east-1:123456789012:parameter/iamap/demo/config",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := extractResources(tt.ev, tt.listed); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("got %v\nwant %v", got, tt.want)
			}
		})
	}
}

func TestExtractResourcesWithoutRegionFallsBackToStar(t *testing.T) {
	var ev trailEvent
	if err := json.Unmarshal([]byte(`{"eventSource":"ssm.amazonaws.com","requestParameters":{"name":"/x"}}`), &ev); err != nil {
		t.Fatal(err)
	}
	if got := extractResources(ev, nil); !reflect.DeepEqual(got, []string{"*"}) {
		t.Errorf("got %v, want [*]", got)
	}
}
