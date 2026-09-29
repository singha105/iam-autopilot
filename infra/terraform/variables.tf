variable "region" {
  description = "AWS region for every resource. us-east-1 keeps IAM calls and app calls in one CloudTrail event history."
  type        = string
  default     = "us-east-1"
}

variable "create_budget" {
  description = "Create the iamap-zero-spend budget. Set false if the account already has an equivalent zero-spend budget."
  type        = bool
  default     = true
}

variable "budget_email" {
  description = "Email address for the zero-spend budget alert. Set it in terraform.tfvars (gitignored), never in code."
  type        = string
  default     = ""
}
