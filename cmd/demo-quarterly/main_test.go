package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"
)

type fakeSSM struct {
	byPathCalls int
	byPathPath  string
	byPathErr   error
}

func (f *fakeSSM) GetParameter(context.Context, *ssm.GetParameterInput, ...func(*ssm.Options)) (*ssm.GetParameterOutput, error) {
	return &ssm.GetParameterOutput{Parameter: &ssmtypes.Parameter{Value: aws.String("cron(0 9 1 */3 ? *)")}}, nil
}

func (f *fakeSSM) GetParametersByPath(_ context.Context, in *ssm.GetParametersByPathInput, _ ...func(*ssm.Options)) (*ssm.GetParametersByPathOutput, error) {
	f.byPathCalls++
	f.byPathPath = aws.ToString(in.Path)
	if f.byPathErr != nil {
		return nil, f.byPathErr
	}
	return &ssm.GetParametersByPathOutput{Parameters: make([]ssmtypes.Parameter, 2)}, nil
}

func newTestApp(f *fakeSSM) (*app, *bytes.Buffer) {
	var buf bytes.Buffer
	return &app{ssm: f, schedule: defaultScheduleName, path: defaultQuarterlyDir, log: slog.New(slog.NewJSONHandler(&buf, nil))}, &buf
}

func TestHandle(t *testing.T) {
	tests := []struct {
		name       string
		event      string
		wantByPath int
		want       Summary
	}{
		{"empty payload is a normal run", `{}`, 0, Summary{Mode: "normal", Schedule: "cron(0 9 1 */3 ? *)"}},
		{"unknown mode is a normal run", `{"mode":"daily"}`, 0, Summary{Mode: "normal", Schedule: "cron(0 9 1 */3 ? *)"}},
		{"quarter-end lists the path", `{"mode":"quarter-end"}`, 1, Summary{Mode: "quarter-end", Schedule: "cron(0 9 1 */3 ? *)", Parameters: 2}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var ev Event
			if err := json.Unmarshal([]byte(tt.event), &ev); err != nil {
				t.Fatal(err)
			}
			f := &fakeSSM{}
			a, _ := newTestApp(f)

			got, err := a.handle(context.Background(), ev)
			if err != nil {
				t.Fatalf("handle: %v", err)
			}
			if got != tt.want {
				t.Errorf("summary = %+v, want %+v", got, tt.want)
			}
			if f.byPathCalls != tt.wantByPath {
				t.Errorf("GetParametersByPath calls = %d, want %d", f.byPathCalls, tt.wantByPath)
			}
			if tt.wantByPath > 0 && f.byPathPath != "/iamap/demo/quarterly/" {
				t.Errorf("GetParametersByPath path = %q", f.byPathPath)
			}
		})
	}
}

func TestQuarterEndDenialIsTheLambdaError(t *testing.T) {
	denied := errors.New("AccessDeniedException: not authorized to perform ssm:GetParametersByPath")
	a, buf := newTestApp(&fakeSSM{byPathErr: denied})

	_, err := a.handle(context.Background(), Event{Mode: modeQuarterEnd})
	if !errors.Is(err, denied) || !strings.Contains(err.Error(), "ssm:GetParametersByPath") {
		t.Fatalf("err = %v, want wrapped GetParametersByPath denial", err)
	}
	var rec map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &rec); err != nil {
		t.Fatalf("want exactly one JSON log line, got %q", buf)
	}
	if rec["mode"] != "quarter-end" || rec["action"] != "ssm:GetParametersByPath" {
		t.Errorf("unexpected log record %v", rec)
	}
}
