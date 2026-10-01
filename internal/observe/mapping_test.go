package observe

import "testing"

func TestActionFor(t *testing.T) {
	tests := []struct {
		source, event string
		want          string
		wantWarning   bool
	}{
		{"ec2.amazonaws.com", "DescribeRegions", "ec2:DescribeRegions", false},
		{"ssm.amazonaws.com", "GetParameter", "ssm:GetParameter", false},
		{"dynamodb.amazonaws.com", "DescribeTable", "dynamodb:DescribeTable", false},
		{"iam.amazonaws.com", "ListRoles", "iam:ListRoles", false},
		// s3 exception: the event is ListBuckets, the IAM action is ListAllMyBuckets.
		{"s3.amazonaws.com", "ListBuckets", "s3:ListAllMyBuckets", false},
		{"s3.amazonaws.com", "GetBucketLocation", "s3:GetBucketLocation", false},
		// lambda exception: strip the API version suffix.
		{"lambda.amazonaws.com", "ListFunctions20150331", "lambda:ListFunctions", false},
		{"lambda.amazonaws.com", "UpdateFunctionConfiguration20150331v2", "lambda:UpdateFunctionConfiguration", false},
		{"lambda.amazonaws.com", "GetFunction", "lambda:GetFunction", false},
		// The suffix rule only applies to lambda.
		{"ec2.amazonaws.com", "Describe20150331", "ec2:Describe20150331", false},
		// monitoring -> cloudwatch.
		{"monitoring.amazonaws.com", "GetMetricStatistics", "cloudwatch:GetMetricStatistics", false},
		// Unknown sources are kept, with a warning.
		{"airflow.amazonaws.com", "ListEnvironments", "airflow:ListEnvironments", true},
		{"weird-source", "DoThing", "weird-source:DoThing", true},
	}
	for _, tt := range tests {
		got, warning := ActionFor(tt.source, tt.event)
		if got != tt.want {
			t.Errorf("ActionFor(%q, %q) = %q, want %q", tt.source, tt.event, got, tt.want)
		}
		if (warning != "") != tt.wantWarning {
			t.Errorf("ActionFor(%q, %q) warning = %q, want warning: %v", tt.source, tt.event, warning, tt.wantWarning)
		}
	}
}

func TestIsDenied(t *testing.T) {
	tests := map[string]bool{
		"AccessDenied":                 true,
		"AccessDeniedException":        true,
		"Client.UnauthorizedOperation": true,
		"UnauthorizedOperation":        true,
		"AuthorizationError":           true,
		"AuthorizationErrorX":          false,
		"ResourceNotFoundException":    false,
		"ParameterNotFound":            false,
		"ThrottlingException":          false,
		"":                             false,
	}
	for code, want := range tests {
		if got := IsDenied(code); got != want {
			t.Errorf("IsDenied(%q) = %v, want %v", code, got, want)
		}
	}
}
