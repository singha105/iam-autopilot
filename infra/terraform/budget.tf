# Alert on the first cent of actual spend. AWS Budgets itself is free for
# budgets without actions.
resource "aws_budgets_budget" "zero_spend" {
  count = var.create_budget ? 1 : 0

  name         = "iamap-zero-spend"
  budget_type  = "COST"
  limit_amount = "0.01"
  limit_unit   = "USD"
  time_unit    = "MONTHLY"

  notification {
    comparison_operator        = "GREATER_THAN"
    threshold                  = 0.01
    threshold_type             = "ABSOLUTE_VALUE"
    notification_type          = "ACTUAL"
    subscriber_email_addresses = [var.budget_email]
  }

  lifecycle {
    precondition {
      condition     = can(regex("^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$", var.budget_email))
      error_message = "budget_email must be a valid email address when create_budget is true (set it in terraform.tfvars)."
    }
  }
}
