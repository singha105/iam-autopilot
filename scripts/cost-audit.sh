#!/usr/bin/env bash
# Read-only audit that this project has created nothing billable.
#
# Fails if any resource tagged Project=iam-autopilot is of a forbidden type, if a
# CloudTrail trail belongs to this project, or if an iamap-* DynamoDB table,
# SSM parameter, log group, Lambda or state machine breaks the zero-cost rules
# in CLAUDE.md. Every call here is a free read (tagging API, describe/list).
set -euo pipefail

region="${AWS_REGION:-${AWS_DEFAULT_REGION:-us-east-1}}"
awsj() { aws --region "$region" --output json "$@"; }
count() { grep -c . || true; }

fail=0
pass() { echo "PASS  $*"; }
bad() {
  echo "FAIL  $*"
  fail=1
}

# 1. Every project-tagged resource, checked against forbidden ARN types.
arns="$(awsj resourcegroupstaggingapi get-resources \
  --tag-filters Key=Project,Values=iam-autopilot \
  --query 'ResourceTagMappingList[].ResourceARN' | jq -r '.[]' | sort)"
echo "Project resources visible to the tagging API ($region): $(count <<<"$arns")"
[ -n "$arns" ] && sed 's/^/      /' <<<"$arns"

forbidden=':cloudtrail:[^:]*:[0-9]*:(trail|eventdatastore)/|:athena:|:glue:|:access-analyzer:|:ec2:[^:]*:[0-9]*:(instance|natgateway|elastic-ip)/|:elasticloadbalancing:|:secretsmanager:|:kms:[^:]*:[0-9]*:key/|:eks:|:ecs:|:apigateway:|:xray:|^arn:aws[a-z-]*:s3:::'
if hits="$(grep -E "$forbidden" <<<"$arns")"; then
  bad "forbidden resource types:"
  sed 's/^/        /' <<<"$hits"
else
  pass "no forbidden resource types among project resources"
fi

# 2. No CloudTrail trail created by this project (event history needs none).
trails="$(awsj cloudtrail describe-trails --include-shadow-trails \
  --query 'trailList[].Name' | jq -r '.[]')"
if ours="$(grep -iE '^iamap-|iam-autopilot' <<<"$trails")"; then
  bad "CloudTrail trail(s) belonging to this project: $(tr '\n' ' ' <<<"$ours")"
else
  pass "no CloudTrail trail created by this project ($(count <<<"$trails") trail(s) in the account, none iamap)"
fi

# 3. DynamoDB: PROVISIONED, capacity 1/1, no GSIs, no streams.
tables="$(awsj dynamodb list-tables --query 'TableNames' | jq -r '.[] | select(startswith("iamap-"))')"
[ -z "$tables" ] && pass "no iamap DynamoDB tables yet"
for t in $tables; do
  d="$(awsj dynamodb describe-table --table-name "$t" --query Table)"
  mode="$(jq -r '.BillingModeSummary.BillingMode // "PROVISIONED"' <<<"$d")"
  rcu="$(jq -r '.ProvisionedThroughput.ReadCapacityUnits' <<<"$d")"
  wcu="$(jq -r '.ProvisionedThroughput.WriteCapacityUnits' <<<"$d")"
  gsis="$(jq -r '(.GlobalSecondaryIndexes // []) | length' <<<"$d")"
  stream="$(jq -r '.StreamSpecification.StreamEnabled // false' <<<"$d")"
  if [ "$mode" = PROVISIONED ] && [ "$rcu" -le 1 ] && [ "$wcu" -le 1 ] && [ "$gsis" = 0 ] && [ "$stream" = false ]; then
    pass "table $t is PROVISIONED ${rcu}/${wcu}, no GSIs, no stream"
  else
    bad "table $t: mode=$mode rcu=$rcu wcu=$wcu gsis=$gsis stream=$stream"
  fi
done

# 4. SSM parameters under /iamap are Standard tier.
advanced="$(awsj ssm describe-parameters \
  --parameter-filters Key=Path,Option=Recursive,Values=/iamap \
  --query 'Parameters[?Tier!=`Standard`].Name' | jq -r '.[]')"
if [ -n "$advanced" ]; then bad "non-Standard SSM parameters: $advanced"; else pass "all /iamap SSM parameters are Standard tier"; fi

# 5. Lambda: arm64, no VPC, at most 256 MB.
fns="$(awsj lambda list-functions \
  --query 'Functions[?starts_with(FunctionName, `iamap-`)].{n:FunctionName,a:Architectures[0],m:MemorySize,v:VpcConfig.VpcId}')"
bad_fns="$(jq -r '.[] | select(.a != "arm64" or .m > 256 or ((.v // "") != "")) | .n' <<<"$fns")"
if [ -n "$bad_fns" ]; then bad "Lambda rules broken by: $bad_fns"; else pass "$(jq length <<<"$fns") iamap Lambda(s): arm64, <=256 MB, no VPC"; fi

# 6. Log groups for iamap Lambdas keep logs 3 days at most.
lgs="$(awsj logs describe-log-groups --log-group-name-prefix /aws/lambda/iamap- \
  --query 'logGroups[].{n:logGroupName,r:retentionInDays}')"
bad_lgs="$(jq -r '.[] | select((.r // 0) == 0 or .r > 3) | .n' <<<"$lgs")"
if [ -n "$bad_lgs" ]; then bad "log groups without <=3 day retention: $bad_lgs"; else pass "$(jq length <<<"$lgs") iamap log group(s) with <=3 day retention"; fi

# 7. Step Functions: iamap state machines are STANDARD (Express is not free).
express="$(awsj stepfunctions list-state-machines \
  --query 'stateMachines[?starts_with(name, `iamap-`) && type!=`STANDARD`].name' | jq -r '.[]')"
if [ -n "$express" ]; then bad "non-STANDARD state machines: $express"; else pass "no EXPRESS iamap state machines"; fi

echo "---"
if [ "$fail" -ne 0 ]; then
  echo "cost-audit: FAILED"
  exit 1
fi
echo "cost-audit: PASSED"
