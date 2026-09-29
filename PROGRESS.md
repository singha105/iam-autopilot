# Progress

Read this and CLAUDE.md at the start of every session.

## Day 1: Foundation, guardrails and demo apps (2026-09-29)

- [x] Step 0 safety checks (identity, event history, OIDC provider, existing budgets)
- [x] CLAUDE.md with zero-cost, safety and working rules
- [x] Repo scaffold, go.mod, Makefile, README, DECISIONS, LICENSE
- [x] Three over-permissioned demo Lambdas (inventory, config-reader, quarterly), unit tested with fakes
- [x] Terraform: budget, permissions boundary, demo roles/policies/functions, DynamoDB, SSM
- [x] autopilot.yaml
- [x] scripts/traffic.sh and scripts/cost-audit.sh
- [x] CI workflow (lint, test, build, terraform fmt/validate; no AWS credentials)
- [x] `make check` passes locally
- [ ] CI green on GitHub (checked right after the Day 1 push; see the Actions tab)
- [x] Deployed with `make apply` (24 resources); budget `iamap-zero-spend` exists
- [x] `make traffic` prints OK for all 15 calls: runs at 18:12Z, 18:15Z and 18:18Z, 15/15 each
  (one extra back-to-back run at 18:15Z, output not kept)
- [x] `lookup-events` shows API calls made by a demo function (DescribeInstances, DescribeRegions,
  ListBuckets, ListFunctions20150331 by iamap-demo-inventory, about 3 minutes after invoke)
- [x] `make cost-audit` passes
- [x] terraform.tfstate, terraform.tfvars and build/ not in git (`git ls-files`)

## Day 2

- [ ] Run `make traffic` first
- [ ] (Day 2 prompt)

## Day 3

- [ ] Run `make traffic` first
- [ ] (Day 3 prompt)

## Day 4

- [ ] Run `make traffic` first
- [ ] (Day 4 prompt)

## Day 5

- [ ] (Day 5 prompt)

## Day 6

- [ ] (Day 6 prompt)

## Facts recorded

- AWS account: the `paved` profile (root login session, `aws login --profile paved`); region us-east-1 (var.region).
- GitHub OIDC provider for token.actions.githubusercontent.com: **does not exist**. Day 5 must create it.
  (The only OIDC provider in the account is Paved's leftover S3-hosted eu-west-2 one; leave it alone.)
- Budgets before Day 1: none. `iamap-zero-spend` is the only budget ($0.01/month, email on ACTUAL > $0.01).
- CloudTrail trails in the account: 0. Event history works without one.
- Go module targets `go 1.25.0`. aws-lambda-go is pinned to v1.54.0 because v1.55+ requires Go 1.26.

## Findings for later days

- **Service-made events under the role session (Day 2 observer).** Event history shows `kms:Decrypt`
  with `Username=iamap-demo-inventory` even though the app never calls KMS. The record has
  `userIdentity.invokedBy`, `userAgent` and `sourceIPAddress` all equal to `lambda.amazonaws.com`: it is
  the Lambda service acting for the function. The observer must drop events whose `invokedBy` is an AWS
  service, or the generator would keep `kms:Decrypt` for no reason.
- **Event names are not always IAM action names (Day 2 observer).** Lambda's ListFunctions is recorded
  as `ListFunctions20150331` (API version suffix). The observer needs an eventName -> IAM action
  normalisation step (strip Lambda's date suffixes; check other services in the recorded fixtures).
- **Blind spot confirmed (Day 3).** After run 1, event history for iamap-demo-config-reader shows
  DescribeTable x5 and GetParameter x5 but no GetItem/PutItem, although every run wrote its item.
  CreateLogStream and Decrypt also appear under the demo sessions and need the same invokedBy check.
- Event history latency observed on Day 1: about 3 minutes from invoke to `lookup-events`.
- `s3:ListBuckets` sees 5 buckets in the account (Paved's). The boundary only permits listing, not reading.

## Next

- Day 2: run `make traffic`, then paste the Day 2 prompt.
