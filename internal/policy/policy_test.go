package policy

import (
	"os"
	"reflect"
	"strings"
	"testing"
)

func TestParseStringOrArray(t *testing.T) {
	doc, err := Parse([]byte(`{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"s3:ListAllMyBuckets","Resource":"*"}}`))
	if err != nil {
		t.Fatal(err)
	}
	want := Statements{{Effect: "Allow", Action: Strings{"s3:ListAllMyBuckets"}, Resource: Strings{"*"}}}
	if !reflect.DeepEqual(doc.Statement, want) {
		t.Errorf("statements = %+v, want %+v", doc.Statement, want)
	}
}

func TestEncodeSortsKeysAndKeepsCondition(t *testing.T) {
	doc := Document{Version: Version, Statement: Statements{{
		Sid: "Deny0", Effect: "Deny", Action: Strings{"iam:*"}, Resource: Strings{"*"},
		Condition: []byte(`{"Bool":{"aws:MultiFactorAuthPresent":"false"}}`),
	}}}
	b, err := doc.Encode()
	if err != nil {
		t.Fatal(err)
	}
	got := string(b)
	order := []string{`"Statement"`, `"Action"`, `"Condition"`, `"Effect"`, `"Resource"`, `"Sid"`, `"Version"`}
	last := -1
	for _, key := range order {
		i := strings.Index(got, key)
		if i < last {
			t.Fatalf("key %s out of order:\n%s", key, got)
		}
		last = i
	}
	if !strings.Contains(got, `"aws:MultiFactorAuthPresent": "false"`) || !strings.HasSuffix(got, "}\n") {
		t.Errorf("unexpected encoding:\n%s", got)
	}
}

// The Day 1 demo policies use "Resource": "*" (a string). Encoding always
// writes arrays, which IAM treats identically; the meaning must survive.
func TestDemoPoliciesRoundTrip(t *testing.T) {
	for _, name := range []string{"inventory", "config-reader", "quarterly"} {
		raw, err := os.ReadFile("../../policies/demo/" + name + ".json")
		if err != nil {
			t.Fatal(err)
		}
		doc, err := Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(doc.Statement[0].Resource, Strings{"*"}) {
			t.Errorf("%s: Resource = %v, want [*]", name, doc.Statement[0].Resource)
		}
		out, err := doc.Encode()
		if err != nil {
			t.Fatal(err)
		}
		again, err := Parse(out)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(doc, again) {
			t.Errorf("%s changed meaning after encode/parse:\n%s", name, out)
		}
	}
}

func TestNonWhitespaceLen(t *testing.T) {
	if got := NonWhitespaceLen([]byte("{ \"a\" :\n\t1 }")); got != 7 {
		t.Errorf("NonWhitespaceLen = %d, want 7", got)
	}
}
