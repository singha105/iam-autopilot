# Architecture decision records

Each entry: context, decision, consequences. Day 6 fills in the full set.

| # | Decision | Status |
|---|----------|--------|
| [ADR-001](#adr-001-standard-library-flag-package-for-the-cli) | Standard library `flag` package for the CLI, not cobra | Accepted (Day 2) |

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
