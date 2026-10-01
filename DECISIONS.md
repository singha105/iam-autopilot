# Architecture decision records

Each entry: context, decision, consequences. Day 6 fills in the full set.

| # | Decision | Status |
|---|----------|--------|
| [ADR-001](#adr-001-standard-library-flag-package-for-the-cli) | Standard library `flag` package for the CLI, not cobra | Accepted (Day 2) |
| [ADR-002](#adr-002-exclude-platform-calls-from-observed-usage) | Exclude calls AWS makes with the role's credentials from observed usage | Accepted (Day 2) |

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
