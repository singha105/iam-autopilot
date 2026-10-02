output "demo_function_names" {
  description = "Demo Lambda function names, keyed by app."
  value       = { for k, f in aws_lambda_function.demo : k => f.function_name }
}

output "demo_role_arns" {
  description = "Demo role ARNs (tagged autopilot:managed=true), keyed by app."
  value       = { for k, r in aws_iam_role.demo : k => r.arn }
}

output "demo_policy_arns" {
  description = "Customer-managed /iamap/managed/ policies the autopilot may tighten, keyed by app."
  value       = { for k, p in aws_iam_policy.demo : k => p.arn }
}

output "demo_boundary_arn" {
  description = "Permissions boundary on every demo role."
  value       = aws_iam_policy.demo_boundary.arn
}

output "demo_table_name" {
  value = aws_dynamodb_table.demo_config.name
}

output "budget_name" {
  value = one(aws_budgets_budget.zero_spend[*].name)
}

output "rollouts_table_name" {
  description = "DynamoDB table holding one record per rollout."
  value       = aws_dynamodb_table.rollouts.name
}

output "github_token_parameter" {
  description = "SSM SecureString parameter (created by hand, not by Terraform) holding the GitHub token."
  value       = local.github_token_parameter
}
