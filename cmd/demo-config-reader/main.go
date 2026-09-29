// Command demo-config-reader is a demo Lambda that reads its config from SSM,
// describes its DynamoDB table, then reads and writes one item.
//
// GetItem and PutItem are DynamoDB data-plane calls: CloudTrail event history
// never records them. That blind spot is deliberate; the autopilot has to keep
// those actions using IAM Access Advisor instead (Day 3).
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	ddbtypes "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
)

const (
	appName          = "iamap-demo-config-reader"
	defaultParam     = "/iamap/demo/config"
	defaultTable     = "iamap-demo-config"
	settingsKeyValue = "settings"
)

type ssmAPI interface {
	GetParameter(context.Context, *ssm.GetParameterInput, ...func(*ssm.Options)) (*ssm.GetParameterOutput, error)
}

type dynamoAPI interface {
	DescribeTable(context.Context, *dynamodb.DescribeTableInput, ...func(*dynamodb.Options)) (*dynamodb.DescribeTableOutput, error)
	GetItem(context.Context, *dynamodb.GetItemInput, ...func(*dynamodb.Options)) (*dynamodb.GetItemOutput, error)
	PutItem(context.Context, *dynamodb.PutItemInput, ...func(*dynamodb.Options)) (*dynamodb.PutItemOutput, error)
}

// Summary is the Lambda's JSON response.
type Summary struct {
	Config      string `json:"config"`
	TableStatus string `json:"tableStatus"`
	ItemFound   bool   `json:"itemFound"`
	Written     bool   `json:"written"`
}

type app struct {
	ssm   ssmAPI
	ddb   dynamoAPI
	param string
	table string
	now   func() time.Time
	log   *slog.Logger
}

func (a *app) key() map[string]ddbtypes.AttributeValue {
	return map[string]ddbtypes.AttributeValue{"pk": &ddbtypes.AttributeValueMemberS{Value: settingsKeyValue}}
}

// handle makes every call even if an earlier one fails; see demo-inventory.
func (a *app) handle(ctx context.Context) (Summary, error) {
	var s Summary
	var errs []error
	fail := func(action string, err error) {
		a.log.Error("aws call failed", "app", appName, "action", action, "error", err.Error())
		errs = append(errs, fmt.Errorf("%s: %w", action, err))
	}

	if out, err := a.ssm.GetParameter(ctx, &ssm.GetParameterInput{Name: aws.String(a.param)}); err != nil {
		fail("ssm:GetParameter", err)
	} else if out.Parameter != nil {
		s.Config = aws.ToString(out.Parameter.Value)
	}

	if out, err := a.ddb.DescribeTable(ctx, &dynamodb.DescribeTableInput{TableName: aws.String(a.table)}); err != nil {
		fail("dynamodb:DescribeTable", err)
	} else if out.Table != nil {
		s.TableStatus = string(out.Table.TableStatus)
	}

	if out, err := a.ddb.GetItem(ctx, &dynamodb.GetItemInput{TableName: aws.String(a.table), Key: a.key()}); err != nil {
		fail("dynamodb:GetItem", err)
	} else {
		s.ItemFound = len(out.Item) > 0
	}

	item := a.key()
	item["config"] = &ddbtypes.AttributeValueMemberS{Value: s.Config}
	item["updatedAt"] = &ddbtypes.AttributeValueMemberS{Value: a.now().UTC().Format(time.RFC3339)}
	if _, err := a.ddb.PutItem(ctx, &dynamodb.PutItemInput{TableName: aws.String(a.table), Item: item}); err != nil {
		fail("dynamodb:PutItem", err)
	} else {
		s.Written = true
	}

	if len(errs) > 0 {
		return s, errors.Join(errs...)
	}
	a.log.Info("config read complete", "app", appName, "summary", s)
	return s, nil
}

func envOr(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	cfg, err := config.LoadDefaultConfig(context.Background())
	if err != nil {
		logger.Error("load aws config", "app", appName, "error", err.Error())
		os.Exit(1)
	}
	a := &app{
		ssm:   ssm.NewFromConfig(cfg),
		ddb:   dynamodb.NewFromConfig(cfg),
		param: envOr("CONFIG_PARAMETER", defaultParam),
		table: envOr("TABLE_NAME", defaultTable),
		now:   time.Now,
		log:   logger,
	}
	lambda.Start(a.handle)
}
