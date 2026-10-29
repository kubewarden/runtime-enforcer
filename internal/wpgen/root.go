// Package wpgen implements the wpgen command line tool, which drafts
// WorkloadPolicy resources from container images.
package wpgen

import (
	"github.com/spf13/cobra"
)

var version = "dev"

// NewRootCmd builds the wpgen command tree.
func NewRootCmd() *cobra.Command {
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
foreign root.`,
		Version:       version,
		SilenceUsage:  true,
		SilenceErrors: false,
	}

	cmd.AddCommand(newImageCmd())
	cmd.AddCommand(newWorkloadCmd())
	cmd.AddCommand(newCheckCmd())

	return cmd
}
