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
