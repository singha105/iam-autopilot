// Command demo-inventory is a demo Lambda that only reads: it lists EC2 regions
// and instances, S3 buckets, Lambda functions and IAM roles, then returns counts.
//
// Its IAM policy (policies/demo/inventory.json) is deliberately far broader than
// these five read calls; the autopilot's job is to shrink it.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"

	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	awslambda "github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

const appName = "iamap-demo-inventory"

type ec2API interface {
	DescribeRegions(context.Context, *ec2.DescribeRegionsInput, ...func(*ec2.Options)) (*ec2.DescribeRegionsOutput, error)
	DescribeInstances(context.Context, *ec2.DescribeInstancesInput, ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error)
}

type s3API interface {
	ListBuckets(context.Context, *s3.ListBucketsInput, ...func(*s3.Options)) (*s3.ListBucketsOutput, error)
}

type lambdaAPI interface {
	ListFunctions(context.Context, *awslambda.ListFunctionsInput, ...func(*awslambda.Options)) (*awslambda.ListFunctionsOutput, error)
}

type iamAPI interface {
	ListRoles(context.Context, *iam.ListRolesInput, ...func(*iam.Options)) (*iam.ListRolesOutput, error)
}

// Summary is the Lambda's JSON response.
type Summary struct {
	Regions   int `json:"regions"`
	Instances int `json:"instances"`
	Buckets   int `json:"buckets"`
	Functions int `json:"functions"`
	Roles     int `json:"roles"`
}

type app struct {
	ec2    ec2API
	s3     s3API
	lambda lambdaAPI
	iam    iamAPI
	log    *slog.Logger
}

// handle makes every call even if an earlier one fails, so a tightened policy
// that breaks several actions shows every AccessDenied at once. Each failure is
// logged as one JSON line and all of them are returned as the Lambda error.
func (a *app) handle(ctx context.Context) (Summary, error) {
	var s Summary
	var errs []error
	fail := func(action string, err error) {
		a.log.Error("aws call failed", "app", appName, "action", action, "error", err.Error())
		errs = append(errs, fmt.Errorf("%s: %w", action, err))
	}

	if out, err := a.ec2.DescribeRegions(ctx, &ec2.DescribeRegionsInput{}); err != nil {
		fail("ec2:DescribeRegions", err)
	} else {
		s.Regions = len(out.Regions)
	}

	if out, err := a.ec2.DescribeInstances(ctx, &ec2.DescribeInstancesInput{MaxResults: aws.Int32(5)}); err != nil {
		fail("ec2:DescribeInstances", err)
	} else {
		for _, r := range out.Reservations {
			s.Instances += len(r.Instances)
		}
	}

	if out, err := a.s3.ListBuckets(ctx, &s3.ListBucketsInput{}); err != nil {
		fail("s3:ListBuckets", err)
	} else {
		s.Buckets = len(out.Buckets)
	}

	if out, err := a.lambda.ListFunctions(ctx, &awslambda.ListFunctionsInput{MaxItems: aws.Int32(5)}); err != nil {
		fail("lambda:ListFunctions", err)
	} else {
		s.Functions = len(out.Functions)
	}

	if out, err := a.iam.ListRoles(ctx, &iam.ListRolesInput{MaxItems: aws.Int32(5)}); err != nil {
		fail("iam:ListRoles", err)
	} else {
		s.Roles = len(out.Roles)
	}

	if len(errs) > 0 {
		return s, errors.Join(errs...)
	}
	a.log.Info("inventory complete", "app", appName, "summary", s)
	return s, nil
}

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	cfg, err := config.LoadDefaultConfig(context.Background())
	if err != nil {
		logger.Error("load aws config", "app", appName, "error", err.Error())
		os.Exit(1)
	}
	a := &app{
		ec2:    ec2.NewFromConfig(cfg),
		s3:     s3.NewFromConfig(cfg),
		lambda: awslambda.NewFromConfig(cfg),
		iam:    iam.NewFromConfig(cfg),
		log:    logger,
	}
	lambda.Start(a.handle)
}
