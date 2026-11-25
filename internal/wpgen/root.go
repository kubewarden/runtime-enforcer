// Package wpgen implements the wpgen command line tool, which drafts
// WorkloadPolicy resources from container images.
package wpgen

import (
	"context"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"
)

var version = "dev"

// NewRootCmd builds the wpgen command tree.
func NewRootCmd() *cobra.Command {
	return newRootCmd(newGlobalOptions())
}

func newRootCmd(g *globalOptions) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "wpgen",
		Short: "Draft WorkloadPolicy resources from container images",
		Long: `wpgen drafts a WorkloadPolicy from the executables found inside container images.

The output should only be considered a starting point for a WorkloadPolicy, as a
container image often contains many executables that the application never
calls. Run the policy in monitor mode first, and preferably rely on the learn
phase of runtime-enforcer to build a policy from the real behavior of the
application.

wpgen only inspects the file system of the image. It cannot consider files on
volumes, or files that the workload creates at runtime.

Colors are only used for highlighting important information: the check verdict,
warnings, notices and errors. With --color=auto (default) colors are only
enabled when the output is a terminal. Setting the environment variable
CLICOLOR_FORCE to a non-empty value other than "0" enables colors unless
NO_COLOR is non-empty, in which case colors are disabled. The command line
settings --color=always and --color=never take precedence over the environment
variables.`,

		Version:       version,
		SilenceUsage:  true,
		SilenceErrors: true,
		PersistentPreRunE: func(_ *cobra.Command, _ []string) error {
			return g.validate()
		},
	}

	cmd.PersistentFlags().StringVar(&g.Color, colorFlag, colorAuto,
		fmt.Sprintf("When to use colors: %s, %s or %s. %s follows NO_COLOR and CLICOLOR_FORCE",
			colorAuto, colorAlways, colorNever, colorAuto))

	cmd.AddCommand(newImageCmd(g))
	cmd.AddCommand(newWorkloadCmd(g))
	cmd.AddCommand(newCheckCmd(g))

	return cmd
}

// exitInterrupted is the exit code when a signal stops wpgen. It is the code
// that a shell uses after Ctrl-C: 128 + SIGINT.
const exitInterrupted = 130

// Execute runs wpgen and returns the exit code. It prints the error of the
// command, unless the command already reported it.
func Execute(ctx context.Context) int {
	return execute(ctx, os.Args[1:], os.Stdin, os.Stdout, os.Stderr)
}

// execute runs wpgen with the given arguments and streams, and returns the
// exit code.
func execute(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	g := newGlobalOptions()
	cmd := newRootCmd(g)
	cmd.SetArgs(args)
	cmd.SetIn(stdin)
	cmd.SetOut(stdout)
	cmd.SetErr(stderr)
	err := cmd.ExecuteContext(ctx)
	return exitCode(ctx, err, stderr, g.painter(stderr))
}

// exitCode prints the error of the command on stderr and returns the exit
// code. When ctx is cancelled, a signal stopped the command: the error is
// only a consequence, so exitCode prints the cause instead.
func exitCode(ctx context.Context, err error, stderr io.Writer, p painter) int {
	switch {
	case err == nil:
		return 0
	case ctx.Err() != nil:
		fmt.Fprintf(stderr, "%s %v\n", p.failure("Interrupted:"), context.Cause(ctx))
		return exitInterrupted
	case !isReported(err):
		fmt.Fprintf(stderr, "%s %v\n", p.failure("Error:"), err)
	}
	return 1
}
