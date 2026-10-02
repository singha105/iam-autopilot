package generate

import "testing"

func TestSameAccess(t *testing.T) {
	c := cat(t)
	scoped := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["ssm:GetParameter"],"Resource":["` + paramARN + `"]}]}`
	tests := []struct {
		name string
		a, b string
		want bool
	}{
		{"wildcard equals its expansion", allow("dynamodb:*"), allow("dynamodb:DescribeTable", "dynamodb:GetItem", "dynamodb:ListTables", "dynamodb:PutItem", "dynamodb:Scan"), true},
		{"fewer actions", allow("ssm:*"), allow("ssm:GetParameter"), false},
		{"same actions, narrower resource", allow("ssm:GetParameter"), scoped, false},
		{"identical scoped", scoped, scoped, true},
		{"different deny", allow("ssm:*"), `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"ssm:*","Resource":"*"},{"Effect":"Deny","Action":"ssm:PutParameter","Resource":"*"}]}`, false},
	}
	for _, tt := range tests {
		got, err := SameAccess(doc(t, tt.a), doc(t, tt.b), c)
		if err != nil || got != tt.want {
			t.Errorf("%s: SameAccess = %v, %v; want %v", tt.name, got, err, tt.want)
		}
	}
}
