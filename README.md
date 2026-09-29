# IAM Least-Privilege Autopilot

> Work in progress: Day 1 of 6. See [PROGRESS.md](PROGRESS.md).

The autopilot tightens over-broad AWS IAM policies safely. For a target IAM role it
observes which API calls the role really made (CloudTrail event history and IAM Access
Advisor), generates a least-privilege policy, replays past calls through the IAM policy
simulator ("shadow mode"), opens a GitHub pull request with the new policy, applies it as
a new managed-policy version once the PR is merged, watches for `AccessDenied` and Lambda
errors, and rolls back automatically by restoring the previous policy version. It is
written in Go, orchestrated by AWS Step Functions, and designed to cost **$0**: no
CloudTrail trail, no Athena, no Secrets Manager, no KMS keys, no always-on compute.

## Quick start (so far)

```bash
aws login --profile paved
export AWS_PROFILE=paved AWS_REGION=us-east-1
make check          # lint, unit tests, terraform fmt + validate (no AWS calls)
make plan           # build the Lambdas and plan the demo infrastructure
make apply          # apply exactly the reviewed plan
make traffic        # invoke each demo app 5 times so CloudTrail has data
make cost-audit     # fail if any forbidden, billable resource type exists
```

The cost and safety rules are in [CLAUDE.md](CLAUDE.md).

## License

MIT
