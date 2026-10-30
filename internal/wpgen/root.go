// Package wpgen implements the wpgen command line tool, which drafts
// WorkloadPolicy resources from container images.
package wpgen

import (
	"context"
	"fmt"

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

The output is a starting point, not a final policy. A container image often
contains many executables that the workload never runs. Run the policy in
monitor mode first, and prefer the learn phase of runtime-enforcer to build
a policy from the real behavior of the workload.

wpgen only sees the file system of the image. It does not see files on
volumes, files that the workload creates at runtime, or executables from a
foreign root.

Colors are used only for the lines that matter: the check verdict, warnings,
notices and errors. With --color=auto, the default, colors are on only when
the output is a terminal. The NO_COLOR environment variable turns them off,
and CLICOLOR_FORCE=1 turns them on. --color=always and --color=never win
over both.`,
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

// Execute runs wpgen and returns the exit code. It prints the error of the
// command, unless the command already reported it.
func Execute(ctx context.Context) int {
	g := newGlobalOptions()
	cmd := newRootCmd(g)
	err := cmd.ExecuteContext(ctx)
	if err == nil {
		return 0
	}
	if !isReported(err) {
		stderr := cmd.ErrOrStderr()
		fmt.Fprintf(stderr, "%s %v\n", g.painter(stderr).failure("Error:"), err)
	}
	return 1
}
