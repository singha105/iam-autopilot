// Command autopilot is the local CLI: observe today; generate, shadow, propose
// and report as later stages land. See ADR-001 for why it uses package flag.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
)

const usage = `autopilot tightens over-broad IAM policies safely.

Usage:
  autopilot <command> [flags]

Commands:
  observe    Build a usage profile for one role from CloudTrail event history
             and IAM Access Advisor (read-only)

Run "autopilot <command> -h" for a command's flags.
`

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	os.Exit(run(ctx, os.Args[1:], os.Stdout, os.Stderr))
}

// run dispatches to a subcommand and returns the process exit code:
// 0 success, 1 runtime error, 2 usage error.
func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	var err error
	switch args[0] {
	case "observe":
		err = runObserve(ctx, args[1:], stdout, stderr)
	case "help", "-h", "-help", "--help":
		fmt.Fprint(stdout, usage)
		return 0
	default:
		fmt.Fprintf(stderr, "autopilot: unknown command %q\n\n%s", args[0], usage)
		return 2
	}
	switch {
	case err == nil:
		return 0
	case errors.Is(err, flag.ErrHelp):
		return 0
	case errors.Is(err, errUsage):
		return 2
	default:
		fmt.Fprintf(stderr, "autopilot %s: %v\n", args[0], err)
		return 1
	}
}

// errUsage marks a flag or argument error already reported to stderr.
var errUsage = errors.New("usage error")
