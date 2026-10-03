# Architecture decision records

Each entry: context, decision, consequences. Every decision below was exercised in a real run; the evidence is in [docs/results.md](docs/results.md) and [PROGRESS.md](PROGRESS.md).

| # | Decision | Status |
|---|----------|--------|
| [ADR-001](#adr-001-standard-library-flag-package-for-the-cli) | Standard library `flag` package for the CLI, not cobra | Accepted (Day 2) |
| [ADR-002](#adr-002-exclude-platform-calls-from-observed-usage) | Exclude calls AWS makes with the role's credentials from observed usage | Accepted (Day 2) |
| [ADR-003](#adr-003-keep-data-plane-actions-only-with-evidence-rule-r4) | Keep unobservable data-plane actions only with evidence (rule R4) | Accepted (Day 3) |
| [ADR-004](#adr-004-iam-policy-simulator-for-shadow-mode-not-access-analyzer-custom-checks) | IAM policy simulator for shadow mode, not Access Analyzer custom checks | Accepted (Day 3) |
| [ADR-005](#adr-005-a-merged-pr-is-the-approval-the-github-token-lives-in-ssm-securestring) | A merged PR is the approval; the GitHub token lives in an SSM SecureString | Accepted (Day 4) |
| [ADR-006](#adr-006-one-managed-policy-per-role-changed-through-policy-versions) | One managed policy per role, changed through policy versions | Accepted (Day 5) |
| [ADR-007](#adr-007-github-actions-approves-through-oidc-scoped-to-this-repos-pull_request-events) | GitHub Actions approves through OIDC, scoped to this repo's pull_request events | Accepted (Day 5) |
| [ADR-008](#adr-008-two-breakage-signals-cloudtrail-accessdenied-and-the-lambda-errors-metric) | Two breakage signals: CloudTrail AccessDenied and the Lambda Errors metric | Accepted (Day 5) |
| [ADR-009](#adr-009-event-history-instead-of-a-trail-and-athena) | Event history instead of a trail and Athena (cost, and the scale-up path) | Accepted (Day 6) |
| [ADR-010](#adr-010-permissions-boundary-on-the-demo-roles) | Permissions boundary on the demo roles (safe to run in a real account) | Accepted (Day 6) |

---

## ADR-001: Standard library `flag` package for the CLI

**Context.** `cmd/autopilot` needs subcommands: `observe`, `generate`, `shadow`,
`propose`, `cancel`, `status` and `report`. Each takes a handful of flags (`--role`, `--days`, `--region`, `--out`).
The two realistic choices are the standard library `flag` package with one `flag.FlagSet`
per subcommand, or `spf13/cobra`.

**Decision.** Use the standard library `flag` package. A small dispatcher in `main.go` maps
the first argument to a subcommand, and each subcommand owns a `flag.FlagSet` and a
`run(ctx, args, stdout) error` function.

**Why.**
- Five subcommands with a few flags each don't need cobra's features (nested command
  trees, generated completions, persistent flags across levels).
- No new dependency tree to audit, keep updated, and ship inside a binary that runs with
  IAM permissions. That matters for a security tool.
- Each subcommand is a plain function that takes args and an `io.Writer`, so it is
  trivially unit-testable without cobra's command plumbing.
- `flag` accepts both `-role` and `--role`, so the documented `--role` style works.

**Consequences.** Help text and usage are written by hand (a few lines per subcommand).
Flags must come before positional arguments, which is standard Go behaviour. If the CLI
grows nested command groups or needs shell completion, revisit this and move to cobra;
because each subcommand is already a standalone function, that migration is mechanical.

---

## ADR-002: Exclude platform calls from observed usage

**Context.** Event history records calls under the role's session that the function's code
never makes. The first live runs found three kinds:

1. `invokedBy: lambda.amazonaws.com` calls, e.g. `kms:Decrypt` of *other* functions'
   environment variables. Lambda makes these to answer the role's own `lambda:ListFunctions`.
2. `logs:CreateLogStream` with user agent `awslambda-worker/1.0`: the Lambda runtime
   creating the log stream at cold start. It has no `invokedBy`.
3. `kms:Decrypt` with encryption context `aws:lambda:FunctionArn`, from a Java SDK while
   the app is written in Go: the runtime decrypting the function's own environment
   variables at cold start. It also has no `invokedBy`.

Counting them as usage would keep `kms:Decrypt` and `logs:*` in generated policies that
don't need them. The quarterly role has no KMS permission at all and its cold-start
`Decrypt` still succeeds.

**Decision.** The observer drops these events from `observedCalls` (and `deniedCalls`) and
adds one warning per (action, caller) with a count, so nothing disappears silently. The
rules live in `platformCaller` in `internal/observe/cloudtrail.go`: `invokedBy` set, user
agent `awslambda-worker`, or `kms:Decrypt` with the `aws:lambda:FunctionArn` context.

**Consequences.** Generated policies stay minimal and match what the code does. The risk
is a platform call that does need the managed policy. The design limits that risk: logging
comes from `AWSLambdaBasicExecutionRole`, which the autopilot never edits; shadow mode
replays observed calls before any change; and the post-apply watch rolls back on the first
`AccessDenied`. The exclusion rules are narrow pattern matches, so a function's own
`kms:Decrypt` (with its own encryption context) is still counted. A test covers this.

---

## ADR-003: Keep data-plane actions only with evidence (rule R4)

**Context.** CloudTrail event history never records data-plane calls (DynamoDB `GetItem`,
S3 `GetObject`, SQS `SendMessage` …); only a paid trail with data events does (forbidden,
see CLAUDE.md). A generator that trusts event history alone would remove them and break
the app. IAM Access Advisor sees them, but only at service level: it says "dynamodb was
used", not which action. The Day 3 brief proposed keeping every configured data-plane
action the current policy grants whenever Access Advisor says the service was used.

The first real run showed two problems with that:

- **inventory** lists buckets and functions. Access Advisor therefore shows s3 and lambda as
  used, so the rule kept `s3:GetObject`, `s3:PutObject`, `s3:DeleteObject` and
  `lambda:InvokeFunction`, all on `*`. That is write access to every object in the account,
  granted on evidence that only shows the code *listed* buckets.
- **config-reader** kept all eight configured DynamoDB data-plane actions, because its
  policy grants `dynamodb:*` and nothing distinguishes `GetItem` from `Scan`.

**Decision.** R4 keeps a service's data-plane actions only with evidence of data access:

1. A concrete resource of the service appears in event history (config-reader's
   `DescribeTable` on `iamap-demo-config`). The actions are scoped to the observed ARNs that
   fit their resource types.
2. The service was used (Access Advisor) and no observed call explains it at all. That is
   pure data-plane use, so the actions are kept on `*`, as in the original brief.

A service seen *only* through calls on `*` (list calls) gets no data-plane actions. A
warning names exactly what was not kept, so the PR reviewer sees the decision. A role can
override the data-plane list per service in `autopilot.yaml` (`dataPlaneActions`) when the
owner knows what the code does; config-reader is set to `dynamodb: [GetItem, PutItem]`.
Every action R4 keeps is labelled kept-unobservable in the summary and the PR.

A service counts as "used" if Access Advisor reports it in the window *or* event history
has calls for it. Access Advisor lags by up to about 4 hours. In the Day 3 run it reported
0 of 6 services for config-reader in the 1-day window. Requiring it would have removed
`GetItem`/`PutItem` and broken the app.

**Consequences.** Proposals stay small and never grant data access on a guess. The cost:
code that lists a bucket and then reads an object it found would lose `s3:GetObject`.
Three things cover that case:

- the warning in the PR;
- the keep-list (`keepActions`);
- the post-apply watch, which rolls back on the first `AccessDenied`.

That sequence is exactly what scenario C showed for the quarter-end job. The real fix
would be data events on a paid trail. The documented scale-up path is a trail plus
Athena, which also removes the need for this heuristic.

---

## ADR-004: IAM policy simulator for shadow mode, not Access Analyzer custom checks

**Context.** Before a proposal is opened as a PR, we want proof that it would not have
denied anything the role actually did. Two AWS features can answer questions like that:

- `iam:SimulateCustomPolicy` evaluates a policy document against concrete
  (action, resource) pairs. It is free.
- Access Analyzer custom policy checks (`CheckNoNewAccess`, `CheckAccessNotGranted`) use
  automated reasoning to compare policies. They are billed per call, about $0.002 each.
  Unused-access analyzers, the other relevant feature, cost about $0.20 per role per month.

**Decision.** Shadow mode replays every observed call (action on the resource it was seen
on), plus every Access Advisor tracked action in the window that CloudTrail never saw (on
`*`), through `SimulateCustomPolicy`. A tracked action that *was* observed is tested only on
its observed resources. Testing it on `*` too demanded more than the role ever used. When
Access Advisor caught up on Day 4, that made correctly scoped `ssm:GetParameter` and
`dynamodb:DescribeTable` look like would-be denials. It sends one
request per resource with up to 50 actions, at 5 requests/second. Any result other than
`allowed` is a would-be denial. The same test set is also simulated against the *current*
policy, and only **regressions** fail: calls the current policy allows and the proposal
denies. A call both policies deny says the test set (or the simulator) is wrong for that
call. It becomes a warning in the PR instead of a failure. On Day 6 the simulator returned
`implicitDeny` for `ssm:GetParametersByPath` on a trailing-slash path ARN even under
`ssm:*`, while live IAM allowed the call. Validation uses Access Analyzer `ValidatePolicy`, which is free (syntax,
security warnings, suggestions). No analyzer is created and no custom check is ever called.

**Why.** The project's hard rule is $0 (CLAUDE.md), and the simulator answers the exact
question asked: "would these past calls still be allowed?". `CheckNoNewAccess` answers a
different question ("does the new policy grant nothing the old one didn't?"). Our
generator already guarantees that by construction (rule R7), and a unit test covers it.

**Consequences.** The simulator only evaluates the identity policy we pass. It ignores
SCPs, the permissions boundary, resource policies and the role's other attached policies
(`AWSLambdaBasicExecutionRole`). That is why platform-only actions (ADR-002) are skipped
in the test set, and listed in the report, instead of being reported as denials. Shadow
mode proves the past calls are still allowed; it cannot predict future rare calls. The
post-apply watch and automatic rollback (ADR-008) cover those.

---

## ADR-005: A merged PR is the approval; the GitHub token lives in an SSM SecureString

**Context.** Tightening a policy can break a workload, so a person must approve every
change. The approval also needs a record: who approved what, when, and what exactly
changed. To open PRs, the autopilot needs a GitHub credential, which must be stored
somewhere the CLI (now) and the rollout Lambda (Day 5) can read it.

**Decision 1: the PR merge is the approval.** `autopilot propose` commits the proposed
policy to the role's `policyFile` on `autopilot/<rolloutId>` and opens a PR. The body
holds the per-service table, kept-unobservable actions, the shadow result, validation
findings and what happens on merge. Merging it is the only way a rollout moves past
`PR_OPEN`; closing it (`autopilot cancel`) ends the rollout. A hidden
`<!-- rolloutId: … -->` marker ties the PR to its DynamoDB record.

- *Why:* the reviewer gets a real diff of the policy file, GitHub records who merged and
  when, branch protection and CODEOWNERS work unchanged, and `main` always shows the
  policy that is (or is about to be) live. No custom approval UI, no extra service.
- *Consequences:* on Day 4, before merge was wired to enforcement, a merge would have
  changed `main` without changing AWS, so that first real PR (#1) was closed unmerged and
  its record marked CANCELLED. Since Day 5 a merge resumes the waiting rollout (ADR-007). Status changes use a DynamoDB condition on the current status,
  so a cancel and an approval cannot both win.

**Decision 2: the token is an SSM Parameter Store SecureString.** `/iamap/github/token`
uses the Standard tier and the AWS-managed `aws/ssm` key. It is created by hand with the
AWS CLI, never by Terraform. The CLI uses `GITHUB_TOKEN` when set, otherwise reads the
parameter with decryption; it never prints it.

- *Why:* Secrets Manager costs $0.40 per secret per month, and a customer-managed KMS
  key $1 per month. Both are forbidden by the $0 rule (CLAUDE.md). A Standard SecureString
  on `aws/ssm` is free and still encrypted at rest, with access controlled by IAM. Keeping
  it out of Terraform keeps the secret out of `terraform.tfstate`.
- *Token scope:* fine-grained, one repository, with Contents, Pull requests and Issues
  read/write. Issues covers the `autopilot` label. Day 4 hit both failure modes: a 401
  from an invalid token and a 403 from a token missing Contents write. Each time the
  rollout record moved to FAILED and was not left active.
- *Account ID:* everything the autopilot writes to GitHub (policy files, PR text,
  comments) carries `${account_id}` instead of the real ID; Terraform renders the files
  with `templatefile`. Added on Day 6 after the generated policies put real ARNs on `main`;
  earlier PR diffs and git history still show it and were not rewritten.
- *Consequences:* no automatic rotation (Secrets Manager's main extra). Rotation is a
  manual `put-parameter --overwrite`, acceptable for a one-repo demo token with an
  expiry date.

---

## ADR-006: One managed policy per role, changed through policy versions

**Context.** The autopilot must apply a tightened policy and be able to undo it within
seconds when something breaks. The options are rewriting an inline policy, attaching a new
managed policy and detaching the old one, or adding a new *version* of one customer-managed
policy.

**Decision.** Each managed role has exactly one customer-managed policy under
`/iamap/managed/` (enforced by `CurrentPolicy`). Enforce calls `CreatePolicyVersion` with
`SetAsDefault=true` and records the old default as `prevVersionId`. Rollback is a single
`SetDefaultPolicyVersion(prevVersionId)` call. Complete keeps the previous version, so a
manual rollback is one documented CLI command. IAM keeps at most 5 versions; when there
are 5, the oldest non-default version is deleted first. Neither the default nor the
rollback target is ever deleted.

**Why.** Rollback is atomic and fast: no detach/attach window and no copy of the old
document to keep. IAM stores both documents. In the Day 5 run, enforcement took about
2 s from approval (`v1` → `v2`). The role's attachments never change, and Terraform
keeps owning the policy *resource* while the autopilot owns its *versions*.

**Consequences.**
- **Retry safety.** Enforce writes `prevVersionId` before `CreatePolicyVersion`. A retried
  Lambda invocation sees the default has already moved and reuses that version instead
  of creating another and losing the real rollback target.
- **Stale proposals.** A proposal is refused if the default version moved after it was
  built.
- **Terraform stays in sync.** The merged PR puts the same JSON in `main` that the version
  holds, so `terraform plan` shows no change after a rollout (verified on Day 5).

---

## ADR-007: GitHub Actions approves through OIDC, scoped to this repo's pull_request events

**Context.** The approval (a merged PR, ADR-005) happens in GitHub; the rollout waits in
AWS. Something in GitHub must tell AWS "PR #N was merged" without long-lived AWS keys in
the repository.

**Decision.**
- **The workflow.** `approve-rollout.yml` runs when a PR into `main` closes and its head
  branch starts with `autopilot/`. It gets a GitHub OIDC token (`id-token: write`) and
  assumes `iamap-github-approver` with `sts:AssumeRoleWithWebIdentity`.
- **The trust conditions.** `aud = sts.amazonaws.com`, and `sub` is this repository's
  `pull_request` subject.
- **What the role can do.** Exactly one thing: invoke `iamap-approver`.
- **What the approver checks.** It trusts nothing in the event. It checks that the PR
  number matches the rollout record, asks the GitHub API whether the PR was really
  merged, and only then calls `SendTaskSuccess` with the task token stored in DynamoDB.
  A PR closed without merging leads to `SendTaskFailure(PRClosed)`, which cancels the
  rollout.

**Immutable subject.** The first real approval failed with
`Not authorized to perform sts:AssumeRoleWithWebIdentity`. This repository uses GitHub's
*immutable subject* format, which embeds the owner and repository IDs:
`repo:singha105@173531525/iam-autopilot@1396239326:pull_request`, not
`repo:singha105/iam-autopilot:pull_request`. The trust policy now uses that form; check a
repository's format with `gh api repos/<owner>/<repo>/actions/oidc/customization/sub`. It
is stricter than the legacy form: a deleted and re-created repository, or a re-registered
account name, can never match. The IDs are public, not secrets. The failure was safe: the
rollout kept waiting at AwaitApproval, and re-running the workflow after the fix approved it.

**Trade-off.** Any `pull_request` run of this repository can assume the role, from a
branch pushed by anyone with write access. That is acceptable here because the role can
only invoke the approver, the approver re-checks the merge with GitHub, and merging
needs write access anyway. Pull requests from forks get no OIDC token with write
permissions. A stricter setup would run the job in a GitHub **environment with required
reviewers** and trust `sub = repo:…:environment:<name>`, so a second person confirms
before AWS is ever called. Another option is `sub` on the merge commit's `ref`. Neither
is needed for a one-person demo.

---

## ADR-008: Two breakage signals: CloudTrail AccessDenied and the Lambda Errors metric

**Context.** After enforcement the autopilot must notice quickly if the tightened policy
broke the workload, using only free signals (no trail, no alarms, no `GetMetricData`).

**Decision.** Every `pollSeconds` (300) until `watch.minutes + lagBufferMinutes` (30 + 15)
have passed since `enforcedAt`, the Watch step checks:

1. **CloudTrail event history.** Any call by the role since `enforcedAt` with an
   authorization error code (`AccessDenied*`, `*UnauthorizedOperation`,
   `AuthorizationError`). It uses the observer's session-issuer filter, so other roles'
   events with the same username never count. The denied *action names* are what the
   revert PR adds to `keepActions`.
2. **The Lambda `Errors` metric** for the function, Sum over 60-second periods through
   `GetMetricStatistics` (free; `GetMetricData` is not used).

Either signal triggers a rollback. If only the metric fired, the rollback still happens,
and the PR comment says the cause could not be tied to a specific action.

**Why two signals.** They are complementary:
- **The metric is fast but blind.** It updates within about a minute, but it does not say
  *which* permission was missing, and it also fires for bugs that have nothing to do with
  IAM.
- **Event history is precise but slow.** It names the denied action and resource, but
  delivery can take up to about 15 minutes (hence the 15-minute lag buffer before a
  rollout is declared done).

The metric catches breakage early; CloudTrail explains it and feeds the keep-list.

**Consequences.**
- A workload error unrelated to IAM during the watch causes a rollback, which is a false
  positive that costs only a re-proposal.
- Code paths that don't run during the 45-minute watch (the quarter-end job) aren't
  covered. Day 6 shows how that is caught later, and the keep-list makes the system
  remember it.
- A denied *data-plane* call (DynamoDB `GetItem`, S3 `GetObject`) is a data event, so
  event history never shows it, denied or not. Only the `Errors` metric notices it, which
  is a third reason for two signals. In that case the rollback cannot name the action.

---

## ADR-009: Event history instead of a trail and Athena

**Context.** The autopilot needs to know which API calls a role made. The standard answer is
a CloudTrail trail delivering to S3 and queried with Athena. That costs storage, Athena
scans and, for data events, $0.10 per 100,000 events, and a second trail costs $2 per
100,000 management events.

**Decision.** Use CloudTrail **event history** (`LookupEvents`): 90 days of management
events, always on, free. The observer pages it at 1.5 requests/second to stay under the
2/second limit.

**Consequences.** $0, and enough for a handful of roles. The costs are real limits:
- 90 days of memory;
- one region;
- slow paging at scale;
- no data events, which created the blind spot handled by rule R4 (ADR-003).

The scale-up path keeps the rest of the system unchanged: an organization trail to S3 with
Athena replaces `observe`'s event source, and the unused-access analyzer adds per-action
last-used data. Only the observer would change.

---

## ADR-010: Permissions boundary on the demo roles

**Context.** The demo runs in a real AWS account that holds other work. Its policies are
deliberately broad (`s3:*`, `ssm:*`, `ec2:*`) so the autopilot has something to shrink.
A bug in a demo app, or in the autopilot, must not be able to touch anything else.

**Decision.** Every demo role carries the permissions boundary `iamap-demo-boundary`. It
allows only:
- read-style calls (`Describe*`, `List*`, `Get*`);
- SSM parameters under `/iamap/demo/*`;
- the one demo DynamoDB table;
- Lambda logging.

The autopilot changes only policies under `/iamap/managed/` on roles tagged
`autopilot:managed=true`. Its own worker role can write policy versions only there.

**Consequences.** The broad policies look dangerous but cannot act outside the demo. The
simulator ignores boundaries (ADR-004), so shadow mode tests the policy alone, which is the
stricter test. A real deployment would drop the demo boundary and keep the path and tag
scoping.
