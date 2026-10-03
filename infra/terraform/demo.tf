# Three deliberately over-permissioned demo apps for the autopilot to tighten.
#
# Each app gets:
#   - a role tagged autopilot:managed=true (the only roles the autopilot may touch)
#   - AWSLambdaBasicExecutionRole for logging (AWS-managed; never touched)
#   - one customer-managed policy under /iamap/managed/, read from policies/demo/
#     (the policy the autopilot shrinks through new policy versions)
#   - the shared permissions boundary below, so however broad that policy looks,
#     the role can only do read-style calls on demo resources in this account.

locals {
  build_dir  = "${path.module}/../../build"
  policy_dir = "${path.module}/../../policies/demo"

  demo_table_arn = "arn:${local.partition}:dynamodb:${var.region}:${local.account_id}:table/iamap-demo-config"

  demo_apps = {
    inventory = {
      cmd = "demo-inventory"
      env = {}
    }
    config-reader = {
      cmd = "demo-config-reader"
      env = {
        CONFIG_PARAMETER = aws_ssm_parameter.demo_config.name
        TABLE_NAME       = aws_dynamodb_table.demo_config.name
      }
    }
    quarterly = {
      cmd = "demo-quarterly"
      env = {
        SCHEDULE_PARAMETER = aws_ssm_parameter.quarterly_schedule.name
        QUARTERLY_PATH     = "/iamap/demo/quarterly/"
      }
    }
  }
}

# --- Permissions boundary -----------------------------------------------------

data "aws_iam_policy_document" "demo_boundary" {
  statement {
    sid    = "ReadOnlyDiscovery"
    effect = "Allow"
    actions = [
      "ec2:Describe*",
      "iam:Get*",
      "iam:List*",
      "lambda:Get*",
      "lambda:List*",
      "s3:GetBucketLocation",
      "s3:ListAllMyBuckets",
    ]
    resources = ["*"]
  }

  statement {
    sid       = "DemoParametersOnly"
    effect    = "Allow"
    actions   = ["ssm:GetParameter*"]
    resources = ["arn:${local.partition}:ssm:${var.region}:${local.account_id}:parameter/iamap/demo/*"]
  }

  statement {
    sid       = "DemoTableOnly"
    effect    = "Allow"
    actions   = ["dynamodb:DescribeTable", "dynamodb:GetItem", "dynamodb:PutItem"]
    resources = [local.demo_table_arn]
  }

  statement {
    sid       = "LambdaLogging"
    effect    = "Allow"
    actions   = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["*"]
  }
}

resource "aws_iam_policy" "demo_boundary" {
  name        = "iamap-demo-boundary"
  path        = "/iamap/boundary/"
  description = "Permissions boundary for the iam-autopilot demo roles: read-style actions on demo resources only."
  policy      = data.aws_iam_policy_document.demo_boundary.json
}

# --- Per-app role, policy, logs and function ----------------------------------

data "aws_iam_policy_document" "lambda_trust" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "demo" {
  for_each = local.demo_apps

  name                 = "iamap-demo-${each.key}-role"
  description          = "Demo role for iamap-${each.value.cmd}; its /iamap/managed/ policy is tightened by the autopilot."
  assume_role_policy   = data.aws_iam_policy_document.lambda_trust.json
  permissions_boundary = aws_iam_policy.demo_boundary.arn

  tags = {
    "autopilot:managed"  = "true"
    "autopilot:function" = "iamap-${each.value.cmd}"
  }
}

resource "aws_iam_role_policy_attachment" "demo_basic_execution" {
  for_each = local.demo_apps

  role       = aws_iam_role.demo[each.key].name
  policy_arn = "arn:${local.partition}:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_iam_policy" "demo" {
  for_each = local.demo_apps

  name        = "iamap-demo-${each.key}-policy"
  path        = "/iamap/managed/"
  description = "Deliberately over-broad demo policy for iamap-${each.value.cmd}; managed by the autopilot through policy versions."
  # The files carry ${account_id} instead of the real ID, so the public repo
  # never shows it (see githubpr.AccountPlaceholder).
  policy = templatefile("${local.policy_dir}/${each.key}.json", { account_id = local.account_id })
}

resource "aws_iam_role_policy_attachment" "demo" {
  for_each = local.demo_apps

  role       = aws_iam_role.demo[each.key].name
  policy_arn = aws_iam_policy.demo[each.key].arn
}

resource "aws_cloudwatch_log_group" "demo" {
  for_each = local.demo_apps

  name              = "/aws/lambda/iamap-${each.value.cmd}"
  retention_in_days = 3
}

data "archive_file" "demo" {
  for_each = local.demo_apps

  type             = "zip"
  source_file      = "${local.build_dir}/${each.value.cmd}/bootstrap"
  output_path      = "${local.build_dir}/${each.value.cmd}.zip"
  output_file_mode = "0755"
}

resource "aws_lambda_function" "demo" {
  for_each = local.demo_apps

  function_name    = "iamap-${each.value.cmd}"
  description      = "iam-autopilot demo app (${each.key})"
  role             = aws_iam_role.demo[each.key].arn
  runtime          = "provided.al2023"
  architectures    = ["arm64"]
  handler          = "bootstrap"
  memory_size      = 128
  timeout          = 15
  filename         = data.archive_file.demo[each.key].output_path
  source_code_hash = data.archive_file.demo[each.key].output_base64sha256

  dynamic "environment" {
    for_each = length(each.value.env) > 0 ? [each.value.env] : []
    content {
      variables = environment.value
    }
  }

  depends_on = [
    aws_cloudwatch_log_group.demo,
    aws_iam_role_policy_attachment.demo,
    aws_iam_role_policy_attachment.demo_basic_execution,
  ]
}

# --- Demo data ----------------------------------------------------------------

resource "aws_dynamodb_table" "demo_config" {
  name           = "iamap-demo-config"
  billing_mode   = "PROVISIONED"
  read_capacity  = 1
  write_capacity = 1
  hash_key       = "pk"

  attribute {
    name = "pk"
    type = "S"
  }

  point_in_time_recovery {
    enabled = false
  }
}

resource "aws_ssm_parameter" "demo_config" {
  name  = "/iamap/demo/config"
  type  = "String"
  tier  = "Standard"
  value = jsonencode({ featureFlag = "blue", maxItems = 5 })
}

resource "aws_ssm_parameter" "quarterly_schedule" {
  name  = "/iamap/demo/quarterly/schedule"
  type  = "String"
  tier  = "Standard"
  value = "cron(0 9 1 1,4,7,10 ? *)"
}

resource "aws_ssm_parameter" "quarterly_targets" {
  name  = "/iamap/demo/quarterly/q-end-targets"
  type  = "String"
  tier  = "Standard"
  value = "ledger,invoices,payroll"
}
