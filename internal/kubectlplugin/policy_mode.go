package kubectlplugin

import (
	"context"
	"fmt"
	"io"

	"github.com/kubewarden/runtime-enforcer/internal/types/policymode"
	securityclient "github.com/kubewarden/runtime-enforcer/pkg/generated/clientset/versioned/typed/api/v1alpha1"
	"github.com/spf13/cobra"
	"k8s.io/kubectl/pkg/util/completion"
)

type policyModeOptions struct {
	commonOptions

	PolicyName string
	Mode       string
}

func newPolicyModeCmdValidArgsFunction(
	deps commonCmdDeps,
) func(cmd *cobra.Command, args []string, toComplete string) ([]cobra.Completion, cobra.ShellCompDirective) {
	return func(_ *cobra.Command, args []string, toComplete string) ([]cobra.Completion, cobra.ShellCompDirective) {
		switch len(args) {
		case 0:
			return completion.CompGetResource(
				deps.f,
				resourceWorkloadPolicies,
				toComplete,
			), cobra.ShellCompDirectiveNoFileComp
		default:
			return nil, cobra.ShellCompDirectiveNoFileComp
		}
	}
}

func newPolicyModeCmd(deps commonCmdDeps, mode string) *cobra.Command {
	use := fmt.Sprintf("%s POLICY_NAME", mode)
	short := fmt.Sprintf("Set WorkloadPolicy mode to %s", mode)

	opts := &policyModeOptions{
		commonOptions: newCommonOptions(deps),
		Mode:          mode,
	}

	cmd := &cobra.Command{
		Use:               use,
		Short:             short,
		Args:              cobra.ExactArgs(1),
		RunE:              runPolicyModeSetCmd(opts),
		ValidArgsFunction: newPolicyModeCmdValidArgsFunction(deps),
	}

	cmd.SetUsageTemplate(subcommandUsageTemplate)

	// Plugin-specific flags
	cmd.Flags().BoolVar(&opts.DryRun, "dry-run", false, "Show what would happen without making any changes")

	return cmd
}

func newPolicyModeProtectCmd(deps commonCmdDeps) *cobra.Command {
	return newPolicyModeCmd(deps, policymode.ProtectString)
}
func newPolicyModeMonitorCmd(deps commonCmdDeps) *cobra.Command {
	return newPolicyModeCmd(deps, policymode.MonitorString)
}

func runPolicyModeSetCmd(opts *policyModeOptions) func(cmd *cobra.Command, args []string) error {
	return func(cmd *cobra.Command, args []string) error {
		opts.PolicyName = args[0]

		return withRuntimeEnforcerClient(cmd, &opts.commonOptions, func(
			ctx context.Context,
			securityClient securityclient.SecurityV1alpha1Interface,
		) error {
			return runPolicyModeSet(ctx, securityClient, opts, opts.ioStreams.Out)
		})
	}
}

func runPolicyModeSet(
	ctx context.Context,
	client securityclient.SecurityV1alpha1Interface,
	opts *policyModeOptions,
	out io.Writer,
) error {
	policy, err := getWorkloadPolicy(ctx, client, opts.Namespace, opts.PolicyName)
	if err != nil {
		return err
	}

	currentMode := policy.Spec.Mode
	targetMode := opts.Mode

	if currentMode == targetMode {
		fmt.Fprintf(
			out,
			"WorkloadPolicy %q in namespace %q is already in %q mode.\n",
			policy.Name,
			policy.Namespace,
			currentMode,
		)
		return nil
	}

	if opts.DryRun {
		fmt.Fprintf(
			out,
			"Would set WorkloadPolicy %q in namespace %q to %q mode.\n",
			policy.Name,
			policy.Namespace,
			targetMode,
		)
	}

	policy.Spec.Mode = targetMode

	if err = updateWorkloadPolicy(ctx, client, opts.Namespace, policy, opts.DryRun); err != nil {
		return err
	}

	fmt.Fprintf(
		out,
		"Successfully set WorkloadPolicy %q in namespace %q to %q mode.\n",
		policy.Name,
		policy.Namespace,
		targetMode,
	)

	return nil
}
