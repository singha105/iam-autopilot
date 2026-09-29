# CLAUDE.md - rules for this repo

## Zero-cost rules (hard rules, never break them)

Allowed: CloudTrail LookupEvents (event history); IAM (roles, customer-managed policies, policy versions, Access Advisor GenerateServiceLastAccessedDetails/GetServiceLastAccessedDetails, SimulateCustomPolicy, permissions boundaries, OIDC provider); Access Analyzer ValidatePolicy only; Lambda (Go, provided.al2023, arm64, 128-256 MB, no VPC); Step Functions STANDARD workflows only; DynamoDB PROVISIONED mode with read and write capacity 1, no GSIs, no PITR, no streams; SSM Parameter Store STANDARD tier with the default aws/ssm key; CloudWatch GetMetricStatistics and Lambda built-in metrics; CloudWatch log groups with retention_in_days = 3; AWS Budgets; STS; Resource Groups Tagging API (read only).

Forbidden (never create, never call): any CloudTrail trail, CloudTrail Lake, data events; Athena; Glue; Access Analyzer analyzers of any kind (unused access, internal, external) and custom policy checks (CheckNoNewAccess, CheckAccessNotGranted, CheckNoPublicAccess); Cost Explorer API (ce:*); Secrets Manager; customer-managed KMS keys; EC2 instances, EKS, ECS, Fargate, NAT gateways, load balancers, Elastic IPs; API Gateway; VPC-attached Lambdas; DynamoDB on-demand; Step Functions EXPRESS; CloudWatch GetMetricData, alarms, dashboards, custom metrics, Logs Insights; X-Ray; S3 buckets (Terraform state stays local).

If any task seems to need a forbidden service, STOP and ask me. Do not look for a workaround on your own.

## Safety rules (the AWS account is my real account)

- Every resource name starts with "iamap-". Every resource has tags Project=iam-autopilot and ManagedBy=terraform.
- The autopilot may only modify customer-managed policies whose IAM path is /iamap/managed/ and that are attached to a role tagged autopilot:managed=true. It must refuse anything else, including its own roles and any AWS-managed policy.
- Never run terraform apply, terraform destroy, or any AWS CLI command that creates, changes or deletes something without first showing me the plan or the exact command and waiting for my yes.
- Terraform state is local (infra/terraform/terraform.tfstate) and must be in .gitignore. Never put secrets in Terraform (the GitHub token is created by hand with the AWS CLI on Day 4).
- Never print or commit AWS keys or tokens. In test fixtures, replace the real account ID with 123456789012.

## Working rules

- Start every session by reading CLAUDE.md and PROGRESS.md.
- End every session by updating PROGRESS.md (done / not done / next), running make check, and committing with a clear message.
- Go 1.25, module github.com/singha105/iam-autopilot, aws-sdk-go-v2. Every package has unit tests using interfaces and recorded fixtures; tests never call AWS.
- Keep output deterministic (sorted keys, sorted statements) so policy diffs are clean.

## Local environment notes

- AWS access is a short-lived session: `aws login --profile paved`, then `export AWS_PROFILE=paved AWS_REGION=us-east-1`. Never use the `default` profile.
- The budget email lives in `infra/terraform/terraform.tfvars`, which is gitignored.
