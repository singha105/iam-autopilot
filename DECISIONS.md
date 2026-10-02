# Architecture decision records

Each entry: context, decision, consequences. Day 6 fills in the full set.

| # | Decision | Status |
|---|----------|--------|
| [ADR-001](#adr-001-standard-library-flag-package-for-the-cli) | Standard library `flag` package for the CLI, not cobra | Accepted (Day 2) |
| [ADR-002](#adr-002-exclude-platform-calls-from-observed-usage) | Exclude calls AWS makes with the role's credentials from observed usage | Accepted (Day 2) |
| [ADR-003](#adr-003-keep-data-plane-actions-only-with-evidence-rule-r4) | Keep unobservable data-plane actions only with evidence (rule R4) | Accepted (Day 3) |
| [ADR-004](#adr-004-iam-policy-simulator-for-shadow-mode-not-access-analyzer-custom-checks) | IAM policy simulator for shadow mode, not Access Analyzer custom checks | Accepted (Day 3) |

---

## ADR-001: Standard library `flag` package for the CLI

**Context.** `cmd/autopilot` needs subcommands: `observe` today, then `generate`, `shadow`,
`propose` and `report`. Each takes a handful of flags (`--role`, `--days`, `--region`, `--out`).
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

That sequence is the same one Day 6 demonstrates for the quarter-end job. The real fix
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

**Decision.** Shadow mode replays every observed call (action on its resource) and every
Access Advisor tracked action in the window through `SimulateCustomPolicy`. It sends one
request per resource with up to 50 actions, at 5 requests/second. Any result other than
`allowed` is a would-be denial and fails `autopilot shadow`. The same test set is also
simulated against the *current* policy; a denial there means the test set is wrong, not
the proposal. Validation uses Access Analyzer `ValidatePolicy`, which is free (syntax,
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
post-apply watch and automatic rollback (Days 4-6) cover those.
