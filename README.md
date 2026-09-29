# IAM Least-Privilege Autopilot

[![CI](https://github.com/singha105/iam-autopilot/actions/workflows/ci.yml/badge.svg)](https://github.com/singha105/iam-autopilot/actions/workflows/ci.yml)
![Go 1.25](https://img.shields.io/badge/go-1.25-00ADD8)
![Terraform](https://img.shields.io/badge/terraform-%E2%89%A51.6-7B42BC)
![Cost: $0](https://img.shields.io/badge/AWS%20cost-%240-2ea44f)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

Most IAM policies grant far more than the workload uses: `s3:*` where the app only lists
buckets, `dynamodb:*` where it reads one table. Shrinking them by hand is slow, and it's
risky because nobody knows which rare code path needs which permission.

The autopilot shrinks a policy the way a careful engineer would. It looks at what the role
really did, proposes a smaller policy as a pull request, applies it only after a human
merges that PR, then watches for breakage and **rolls back by itself within seconds** if
anything gets denied.

It is written in Go, orchestrated by AWS Step Functions, and built to cost **$0**: it uses
only features that are free outright or sit far inside AWS's always-free allowances.

> **Status: Day 1 of 6 done.** The foundation, cost guardrails, demo workloads and CI are
> built and deployed. The autopilot logic itself (observe → generate → shadow → PR → enforce
> → watch → rollback) arrives on Days 2–6. See [PROGRESS.md](PROGRESS.md) for the live checklist.

## How a rollout works

One rollout tightens one role's policy:

```mermaid
flowchart LR
    A[Observe<br/>CloudTrail event history<br/>+ IAM Access Advisor] --> B[Generate<br/>least-privilege policy]
    B --> C{Shadow mode<br/>replay past calls in the<br/>IAM policy simulator}
    C -- any call denied --> S[Stop: report only]
    C -- all allowed --> D[Open GitHub PR<br/>with the policy diff]
    D -- human merges --> E[Enforce<br/>new policy version]
    E --> F{Watch<br/>AccessDenied in CloudTrail<br/>+ Lambda Errors metric}
    F -- clean window --> G[Done]
    F -- one denial --> H[Roll back<br/>SetDefaultPolicyVersion]
    H --> I[Revert PR adds the action<br/>to the keep-list]
```

1. **Observe.** CloudTrail event history lists every management API call the role made
   in the last 90 days, with parameters, so resources can be scoped to exact ARNs. IAM
   Access Advisor lists which services the role touched at all, including data-plane calls.
2. **Generate.** Build the smallest policy that covers the observed calls. Output is
   deterministic (sorted actions, statements and keys), so PR diffs are clean.
3. **Shadow.** Replay every observed call through the IAM policy simulator. If any call
   would be denied, stop and report instead of proposing.
4. **Propose.** Open a pull request that changes `policies/demo/<app>.json`. The merge is
   the approval: every change has a reviewer, a diff and a record in Git.
5. **Enforce.** GitHub Actions calls a small approver Lambda through OIDC (no AWS keys in
   GitHub), which creates a new version of the customer-managed policy.
6. **Watch.** For the watch window, poll two signals. The Lambda `Errors` metric shows up
   within about a minute; CloudTrail `AccessDenied` events confirm *which* action was denied.
7. **Roll back.** One denial triggers `SetDefaultPolicyVersion` back to the previous version,
   which takes seconds. A revert PR adds the denied action to that role's keep-list, so the
   system learns rare actions such as a job that only runs at quarter end.

### The data-plane blind spot, handled on purpose

CloudTrail event history never records data-plane calls such as DynamoDB `GetItem` or S3
`GetObject`; only a paid trail with data events does. Rather than pay for one, the
generator keeps a service's data-plane actions when Access Advisor shows that service was
used, scopes them to resources it did see, and flags them in the PR for a human to review.
The list of those actions lives in [`autopilot.yaml`](autopilot.yaml).

This is real, not theoretical. After the Day 1 traffic runs, event history for
`iamap-demo-config-reader` shows its `DescribeTable` and `GetParameter` calls, but no
`GetItem` or `PutItem`, even though every run wrote its DynamoDB item.

## Safety model

The autopilot is built to run in an account that already holds other work.

- **Narrow blast radius.** It only ever modifies customer-managed policies under the IAM
  path `/iamap/managed/` that are attached to roles tagged `autopilot:managed=true`. It
  refuses everything else, including its own roles and any AWS-managed policy.
- **One policy per role, changed through versions.** Rollback is a single API call.
- **Permissions boundary on the demo roles.** The demo policies are deliberately far too
  broad (`ec2:*`, `s3:*`, `ssm:*` …), because that is the point of the demo. The
  `iamap-demo-boundary` boundary caps what those roles can *actually* do: read-style calls,
  SSM parameters under `/iamap/demo/*`, and one DynamoDB table. However broad the policy
  looks, a demo role can't touch other buckets, roles or data.
- **No stored credentials.** Local work uses a short-lived `aws login` session. CI has no
  AWS credentials at all. The GitHub token for opening PRs is stored by hand in SSM
  Parameter Store (Day 4), never in Terraform or Git.
- **Humans approve every change.** Nothing is applied without a merged PR, and Terraform
  changes go through a saved, reviewed plan (`make plan` then `make apply`).

## Zero-cost design

| Uses (free) | Why it costs $0 |
|---|---|
| CloudTrail event history (`LookupEvents`) | Always on, 90 days, free; no trail is created |
| IAM Access Advisor, policy simulator, Access Analyzer `ValidatePolicy` | Free IAM features |
| Lambda (Go, arm64, 128–256 MB, no VPC) | Far inside the always-free 1M requests a month |
| Step Functions **Standard** | About 30 state transitions per rollout, inside 4,000 free a month |
| DynamoDB **provisioned** 1 RCU / 1 WCU | Inside the always-free 25 units |
| SSM Parameter Store, standard tier, default `aws/ssm` key | Free |
| CloudWatch `GetMetricStatistics`, built-in Lambda metrics, 3-day log retention | Inside the free allowances |
| IAM roles and policies, GitHub OIDC provider, AWS Budgets | Free |
| GitHub Actions | Free on a public repo |

Deliberately **not** used: CloudTrail trails, CloudTrail Lake and data events; Athena; Glue;
Access Analyzer analyzers and custom policy checks; the Cost Explorer API; Secrets
Manager; customer-managed KMS keys; EC2, EKS, ECS, NAT gateways, load balancers, API
Gateway and VPC-attached Lambdas; DynamoDB on-demand; Step Functions Express; CloudWatch
alarms, dashboards and `GetMetricData`; X-Ray; an S3 bucket for Terraform state (state
stays local and gitignored). The full rules are in [CLAUDE.md](CLAUDE.md).

Two guardrails enforce this:

- a `$0.01` monthly budget (`iamap-zero-spend`) that emails on the first cent of actual spend;
- `make cost-audit`, a read-only script that fails if any resource tagged
  `Project=iam-autopilot` is of a forbidden type, if a CloudTrail trail belongs to the
  project, or if a table, parameter, Lambda, log group or state machine breaks the rules.

## The demo workloads

Three small Go Lambdas give the autopilot something real to tighten. Each one returns every
AWS error as the Lambda error, so it shows in the `Errors` metric, and logs it as one JSON line.

| Function | What it calls | Over-broad policy it starts with |
|---|---|---|
| `iamap-demo-inventory` | `ec2:DescribeRegions`, `ec2:DescribeInstances`, `s3:ListBuckets`, `lambda:ListFunctions`, `iam:ListRoles` | `ec2:*`, `s3:*`, `lambda:*`, `iam:Get*`, `iam:List*`, `sqs:*`, `sns:*` |
| `iamap-demo-config-reader` | `ssm:GetParameter`, `dynamodb:DescribeTable`, then `GetItem` and `PutItem` (data-plane, invisible to event history) | `ssm:*`, `dynamodb:*`, `sqs:*`, `sns:*`, `kms:Decrypt` |
| `iamap-demo-quarterly` | `ssm:GetParameter`; with `{"mode":"quarter-end"}` it also calls `ssm:GetParametersByPath` | `ssm:*`, `ec2:Describe*`, `logs:*`, `sns:*` |

The quarterly app's rare path is the rollback demo. The traffic script never sends
`quarter-end`, so the autopilot never sees `GetParametersByPath` and removes it. Triggering
quarter-end afterwards causes a real `AccessDenied` and an automatic rollback.

## Getting started

### Prerequisites

AWS CLI v2, Terraform 1.6+, Go 1.25+, `make`, `jq`, and an AWS account you can log in to
with a short-lived session.

### Deploy the foundation

```bash
aws login --profile <your-profile>
export AWS_PROFILE=<your-profile> AWS_REGION=us-east-1

cp infra/terraform/terraform.tfvars.example infra/terraform/terraform.tfvars
# edit budget_email in terraform.tfvars (gitignored)

make check        # vet, gofmt, race tests, terraform fmt + validate (no AWS calls)
make plan         # build the arm64 Lambdas, write infra/terraform/tfplan
make apply        # apply exactly that reviewed plan, nothing else
make traffic      # invoke each demo Lambda 5 times; prints OK/ERROR per call
make cost-audit   # read-only check that nothing billable exists
```

CloudTrail event history takes a few minutes to show calls (up to about 15), and Access
Advisor data can lag by up to 4 hours, so run `make traffic` a few times before observing.

Check that the demo calls were recorded:

```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=Username,AttributeValue=iamap-demo-inventory \
  --max-results 5
```

### Tear down

```bash
make destroy      # interactive terraform destroy
```

### Make targets

| Target | What it does |
|---|---|
| `build` | Builds every `cmd/*` for linux/arm64 into `build/<name>/bootstrap` (`CGO_ENABLED=0`, `-tags lambda.norpc`) |
| `test` | `go test ./... -race` |
| `lint` | `go vet` and a `gofmt` check |
| `tf-fmt` / `tf-validate` | `terraform fmt -check`, then `init -backend=false` and `validate` |
| `check` | `lint` + `test` + `tf-fmt` + `tf-validate` |
| `plan` / `apply` | Build, then plan to `tfplan`; apply only that saved plan |
| `traffic` / `cost-audit` | Run `scripts/traffic.sh` / `scripts/cost-audit.sh` |
| `destroy` | Interactive `terraform destroy` |

## Repository layout

```
cmd/autopilot/            CLI: observe, generate, shadow, propose, report   (Days 2-4)
cmd/worker/               one Lambda binary; MODE=worker or MODE=approver  (Days 4-5)
cmd/demo-*/               the three demo Lambdas                           (Day 1)
internal/observe/         CloudTrail event history + Access Advisor -> usage profile
internal/catalog/         embedded IAM action catalog, wildcard expansion
internal/generate/        least-privilege policy + summary
internal/shadow/          policy simulator replay
internal/githubpr/        branch, commit, PR, comments
internal/store/           DynamoDB rollout records
internal/rollout/         enforce, watch and rollback steps
policies/demo/            the managed policy JSON that Terraform reads and PRs edit
statemachine/             Step Functions definition (rollout.asl.json)
infra/terraform/          all AWS resources; local state, gitignored
scripts/                  traffic.sh, cost-audit.sh
testdata/                 recorded API responses, account ID redacted
autopilot.yaml            roles, keep-lists, data-plane actions, watch window
CLAUDE.md                 hard zero-cost and safety rules
PROGRESS.md               day-by-day checklist and findings
DECISIONS.md              architecture decision records
```

## Engineering notes

- **Testing.** Code is unit-tested behind small interfaces with fakes and recorded fixtures;
  tests never call AWS. The demo apps are covered today, and each autopilot package gets its
  tests as it lands. Recorded fixtures replace the real account ID with `123456789012`.
- **CI.** GitHub Actions runs lint, race tests and the arm64 build on Go 1.25, then
  `terraform fmt`, `init -backend=false` and `validate`, with pinned action SHAs and no
  AWS credentials.
- **Findings from the first deploy** (details in [PROGRESS.md](PROGRESS.md)):
  - The Lambda service itself makes calls under the function's role session (`kms:Decrypt`,
    `logs:CreateLogStream`, with `invokedBy: lambda.amazonaws.com`). The observer must
    filter these out, or the tightened policy would keep permissions the app never uses.
  - Event names are not always IAM action names: Lambda's `ListFunctions` is recorded as
    `ListFunctions20150331`, so the observer has to map event names to IAM actions.
- **Decisions.** The reasoning behind each design choice is recorded in [DECISIONS.md](DECISIONS.md).

## License

[MIT](LICENSE) © 2026 Arnab Singh
