package observe

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
)

func TestRedact(t *testing.T) {
	in := `{"arn":"arn:aws:iam::987654321098:role/r","recipientAccountId":"987654321098","accessKeyId":"ASIAZZZZZZZZZZZZZZZZ","other":"AKIAABCDEFGHIJKLMNOP","short":"ASIA123"}`
	got := string(Redact([]byte(in), "987654321098"))
	if strings.Contains(got, "987654321098") {
		t.Errorf("account ID not redacted: %s", got)
	}
	if strings.Count(got, FixtureAccountID) != 2 {
		t.Errorf("want 2 replacements: %s", got)
	}
	if strings.Contains(got, "ASIAZZZZ") || strings.Contains(got, "AKIAABCD") {
		t.Errorf("access key IDs not redacted: %s", got)
	}
	if !strings.Contains(got, `"short":"ASIA123"`) {
		t.Errorf("non-key string changed: %s", got)
	}
}

func TestRecordingIAMWritesRedactedNumberedFiles(t *testing.T) {
	dir := t.TempDir()
	rec := &Recorder{Dir: dir, AccountID: "987654321098"}
	inner := &fakeIAM{
		role: &iam.GetRoleOutput{Role: &iamtypes.Role{Arn: aws.String("arn:aws:iam::987654321098:role/r")}},
		tagPages: []*iam.ListRoleTagsOutput{
			{Tags: []iamtypes.Tag{{Key: aws.String("a"), Value: aws.String("1")}}, IsTruncated: true, Marker: aws.String("m")},
			{Tags: []iamtypes.Tag{{Key: aws.String("b"), Value: aws.String("2")}}},
		},
	}
	c := RecordingIAM{Inner: inner, Rec: rec}
	ctx := context.Background()
	if _, err := c.GetRole(ctx, &iam.GetRoleInput{}); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if _, err := c.ListRoleTags(ctx, &iam.ListRoleTagsInput{}); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"get-role-001.json", "list-role-tags-001.json", "list-role-tags-002.json"} {
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("missing fixture: %v", err)
		}
		if strings.Contains(string(b), "987654321098") {
			t.Errorf("%s contains the real account ID", name)
		}
	}
}
