# Resources the autopilot itself uses (the demo apps live in demo.tf).

# One item per rollout: status, proposed policy, PR and version IDs, metrics.
# Provisioned 1/1 sits inside DynamoDB's always-free 25 RCU / 25 WCU.
resource "aws_dynamodb_table" "rollouts" {
  name           = "iamap-rollouts"
  billing_mode   = "PROVISIONED"
  read_capacity  = 1
  write_capacity = 1
  hash_key       = "rolloutId"

  attribute {
    name = "rolloutId"
    type = "S"
  }

  point_in_time_recovery {
    enabled = false
  }
}

# The GitHub token lives in SSM Parameter Store as a SecureString created by
# hand with the AWS CLI (see PROGRESS.md, Day 4). It is deliberately NOT a
# Terraform resource: Terraform would copy the secret into local state. The
# autopilot only needs its name.
locals {
  github_token_parameter = "/iamap/github/token"
}

# --- The autopilot's own Lambdas: one binary, two functions, two roles --------

locals {
  rollouts_table_arn = aws_dynamodb_table.rollouts.arn
  token_param_arn    = "arn:${local.partition}:ssm:${var.region}:${local.account_id}:parameter${local.github_token_parameter}"
  autopilot_env = {
    TABLE_NAME      = aws_dynamodb_table.rollouts.name
    GITHUB_REPO     = "singha105/iam-autopilot"
    GITHUB_BRANCH   = "main"
    CONFIG_PATH     = "autopilot.yaml"
    TOKEN_PARAMETER = local.github_token_parameter
  }
}

data "archive_file" "worker" {
  type             = "zip"
  source_file      = "${local.build_dir}/worker/bootstrap"
  output_path      = "${local.build_dir}/worker.zip"
  output_file_mode = "0755"
}

resource "aws_cloudwatch_log_group" "worker" {
  name              = "/aws/lambda/iamap-worker"
  retention_in_days = 3
}

resource "aws_cloudwatch_log_group" "approver" {
  name              = "/aws/lambda/iamap-approver"
  retention_in_days = 3
}

# The worker role is our own least-privilege policy, written by hand. Every
# action that supports resource-level permissions is scoped; the ones in
# AnyResourceReadOnly support only "*" (checked against the catalog).
data "aws_iam_policy_document" "worker" {
  statement {
    sid    = "AnyResourceReadOnly"
    effect = "Allow"
    actions = [
      "access-analyzer:ValidatePolicy",
      "cloudtrail:LookupEvents",
      "cloudwatch:GetMetricStatistics",
      "iam:GetServiceLastAccessedDetails",
      "iam:SimulateCustomPolicy",
    ]
    resources = ["*"]
  }

  statement {
    sid    = "ReadAutopilotRoles"
    effect = "Allow"
    actions = [
      "iam:GenerateServiceLastAccessedDetails",
      "iam:GetRole",
      "iam:ListAttachedRolePolicies",
      "iam:ListRoleTags",
    ]
    resources = ["arn:${local.partition}:iam::${local.account_id}:role/iamap-*"]
  }

  statement {
    sid    = "ManagedPoliciesOnly"
    effect = "Allow"
    actions = [
      "iam:CreatePolicyVersion",
      "iam:DeletePolicyVersion",
      "iam:GetPolicy",
      "iam:GetPolicyVersion",
      "iam:ListPolicyVersions",
      "iam:SetDefaultPolicyVersion",
    ]
    resources = ["arn:${local.partition}:iam::${local.account_id}:policy/iamap/managed/*"]
  }

  statement {
    sid       = "RolloutRecords"
    effect    = "Allow"
    actions   = ["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:Scan", "dynamodb:UpdateItem"]
    resources = [local.rollouts_table_arn]
  }

  statement {
    sid       = "GitHubToken"
    effect    = "Allow"
    actions   = ["ssm:GetParameter"]
    resources = [local.token_param_arn]
  }
}

data "aws_iam_policy_document" "approver" {
  statement {
    sid       = "RolloutRecords"
    effect    = "Allow"
    actions   = ["dynamodb:GetItem", "dynamodb:UpdateItem"]
    resources = [local.rollouts_table_arn]
  }

  # SendTaskSuccess/SendTaskFailure support no resource types, so an ARN here
  # would never match and every approval would be denied. The control is the
  # task token: unguessable, single-use, stored only in the rollout record.
  statement {
    sid       = "ResumeRollout"
    effect    = "Allow"
    actions   = ["states:SendTaskFailure", "states:SendTaskSuccess"]
    resources = ["*"]
  }

  statement {
    sid       = "GitHubToken"
    effect    = "Allow"
    actions   = ["ssm:GetParameter"]
    resources = [local.token_param_arn]
  }
}

resource "aws_iam_role" "worker" {
  name               = "iamap-worker-role"
  description        = "Runs the autopilot's rollout steps."
  assume_role_policy = data.aws_iam_policy_document.lambda_trust.json
}

resource "aws_iam_role_policy" "worker" {
  name   = "iamap-worker"
  role   = aws_iam_role.worker.id
  policy = data.aws_iam_policy_document.worker.json
}

resource "aws_iam_role_policy_attachment" "worker_basic" {
  role       = aws_iam_role.worker.name
  policy_arn = "arn:${local.partition}:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_iam_role" "approver" {
  name               = "iamap-approver-role"
  description        = "Approves a rollout after its PR is merged."
  assume_role_policy = data.aws_iam_policy_document.lambda_trust.json
}

resource "aws_iam_role_policy" "approver" {
  name   = "iamap-approver"
  role   = aws_iam_role.approver.id
  policy = data.aws_iam_policy_document.approver.json
}

resource "aws_iam_role_policy_attachment" "approver_basic" {
  role       = aws_iam_role.approver.name
  policy_arn = "arn:${local.partition}:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_lambda_function" "worker" {
  function_name    = "iamap-worker"
  description      = "iam-autopilot rollout steps (MODE=worker)"
  role             = aws_iam_role.worker.arn
  runtime          = "provided.al2023"
  architectures    = ["arm64"]
  handler          = "bootstrap"
  memory_size      = 256
  timeout          = 300
  filename         = data.archive_file.worker.output_path
  source_code_hash = data.archive_file.worker.output_base64sha256

  environment {
    variables = merge(local.autopilot_env, { MODE = "worker" })
  }

  depends_on = [aws_cloudwatch_log_group.worker, aws_iam_role_policy.worker, aws_iam_role_policy_attachment.worker_basic]
}

resource "aws_lambda_function" "approver" {
  function_name    = "iamap-approver"
  description      = "iam-autopilot PR-merge approver (MODE=approver)"
  role             = aws_iam_role.approver.arn
  runtime          = "provided.al2023"
  architectures    = ["arm64"]
  handler          = "bootstrap"
  memory_size      = 128
  timeout          = 30
  filename         = data.archive_file.worker.output_path
  source_code_hash = data.archive_file.worker.output_base64sha256

  environment {
    variables = merge(local.autopilot_env, { MODE = "approver" })
  }

  depends_on = [aws_cloudwatch_log_group.approver, aws_iam_role_policy.approver, aws_iam_role_policy_attachment.approver_basic]
}
