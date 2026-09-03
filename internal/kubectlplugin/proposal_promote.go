package kubectlplugin

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/kubewarden/runtime-enforcer/api/v1alpha1"
	"github.com/kubewarden/runtime-enforcer/internal/types/policymode"
	securityclient "github.com/kubewarden/runtime-enforcer/pkg/generated/clientset/versioned/typed/api/v1alpha1"
	"github.com/spf13/cobra"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/kubectl/pkg/util/completion"
)

type proposalPromoteOptions struct {
	commonOptions

	ProposalName string
	Mode         string
}

func newProposalPromoteCmdValidArgsFunction(
	deps commonCmdDeps,
) func(cmd *cobra.Command, args []string, toComplete string) ([]cobra.Completion, cobra.ShellCompDirective) {
	return func(_ *cobra.Command, args []string, toComplete string) ([]cobra.Completion, cobra.ShellCompDirective) {
		switch len(args) {
		case 0:
			return completion.CompGetResource(
				deps.f,
				"workloadpolicyproposals",
				toComplete,
			), cobra.ShellCompDirectiveNoFileComp
		default:
			return nil, cobra.ShellCompDirectiveNoFileComp
		}
	}
}

func newProposalPromoteCmd(deps commonCmdDeps) *cobra.Command {
	opts := &proposalPromoteOptions{
		commonOptions: newCommonOptions(deps),
		Mode:          policymode.MonitorString,
	}

	cmd := &cobra.Command{
		Use:               "promote PROPOSAL_NAME",
		Short:             "Promote WorkloadPolicyProposal to WorkloadPolicy",
		Long:              "Promote WorkloadPolicyProposal to WorkloadPolicy. This will trigger the creation of a WorkloadPolicy.",
		Args:              cobra.ExactArgs(1),
		ValidArgsFunction: newProposalPromoteCmdValidArgsFunction(deps),
		RunE:              runProposalPromoteCmd(opts),
	}

	cmd.SetUsageTemplate(subcommandUsageTemplate)

	// Plugin-specific flags
	cmd.Flags().BoolVar(&opts.DryRun, "dry-run", false, "Show what would happen without making any changes")
	cmd.Flags().StringVar(
		&opts.Mode,
		"mode",
		policymode.MonitorString,
		fmt.Sprintf("Policy mode for the promoted WorkloadPolicy (%s or %s)", policymode.MonitorString, policymode.ProtectString),
	)

	return cmd
}

func runProposalPromoteCmd(opts *proposalPromoteOptions) func(cmd *cobra.Command, args []string) error {
	return func(cmd *cobra.Command, args []string) error {
		opts.ProposalName = args[0]

		return withRuntimeEnforcerClient(cmd, &opts.commonOptions, func(
			ctx context.Context,
			client securityclient.SecurityV1alpha1Interface,
		) error {
			return runProposalPromote(ctx, client, opts, opts.ioStreams.Out)
		})
	}
}

func runProposalPromote(
	ctx context.Context,
	client securityclient.SecurityV1alpha1Interface,
	opts *proposalPromoteOptions,
	out io.Writer,
) error {
	if !policymode.IsValid(opts.Mode) {
		return fmt.Errorf(
			"invalid mode %q: must be %q or %q",
			opts.Mode,
			policymode.MonitorString,
			policymode.ProtectString,
		)
	}

	proposal, err := client.WorkloadPolicyProposals(opts.Namespace).Get(ctx, opts.ProposalName, metav1.GetOptions{})
	if err != nil {
		if apierrors.IsNotFound(err) {
			return fmt.Errorf("workloadpolicyproposal %q not found in namespace %q", opts.ProposalName, opts.Namespace)
		}
		return fmt.Errorf(
			"failed to get WorkloadPolicyProposal %q in namespace %q: %w",
			opts.ProposalName,
			opts.Namespace,
			err,
		)
	}

	if _, hasPromotionLabel := proposal.HasPromotionLabel(); hasPromotionLabel {
		fmt.Fprintf(
			out,
			"WorkloadPolicyProposal %q in namespace %q is already promoted to WorkloadPolicy.\n",
			proposal.Name,
			proposal.Namespace,
		)
		return nil
	}

	updateOptions := metav1.UpdateOptions{}
	if opts.DryRun {
		updateOptions.DryRun = []string{metav1.DryRunAll}
	}

	proposal.SetPromotionLabel(opts.Mode)

	if _, err = client.WorkloadPolicyProposals(opts.Namespace).
		Update(ctx, proposal, updateOptions); err != nil {
		if apierrors.IsConflict(err) {
			return fmt.Errorf(
				"WorkloadPolicyProposal %q in namespace %q was modified concurrently",
				proposal.Name,
				proposal.Namespace,
			)
		}
		return fmt.Errorf(
			"failed to update WorkloadPolicyProposal %q in namespace %q: %w",
			proposal.Name,
			proposal.Namespace,
			err,
		)
	}

	if opts.DryRun {
		fmt.Fprintf(
			out,
			"WorkloadPolicyProposal %q in namespace %q can be promoted to WorkloadPolicy in %q mode.\nRerun without '--dry-run' to apply the changes.\n",
			proposal.Name,
			proposal.Namespace,
			opts.Mode,
		)
		// We need to return here because we cannot wait for the resource to be created in --dry-run mode
		return nil
	}

	fmt.Fprintf(
		out,
		"Promoted WorkloadPolicyProposal %q in namespace %q to WorkloadPolicy in %q mode.\n",
		proposal.Name,
		proposal.Namespace,
		opts.Mode,
	)

	policy, err := waitForWorkloadPolicy(ctx, client, opts.Namespace, opts.ProposalName)
	if err != nil {
		return fmt.Errorf("policy promotion did not complete successfully: %w", err)
	}

	fmt.Fprintf(out, "WorkloadPolicy %q in namespace %q has been created.\n", policy.Name, policy.Namespace)

	return nil
}

func waitForWorkloadPolicy(
	ctx context.Context,
	client securityclient.SecurityV1alpha1Interface,
	namespace, name string,
) (*v1alpha1.WorkloadPolicy, error) {
	ticker := time.NewTicker(defaultPollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf(
				"stopped waiting for WorkloadPolicy %q in namespace %q to be created: %w",
				name,
				namespace,
				ctx.Err(),
			)
		case <-ticker.C:
			policy, err := client.WorkloadPolicies(namespace).Get(ctx, name, metav1.GetOptions{})
			if err != nil {
				if apierrors.IsNotFound(err) {
					continue
				}
				return nil, fmt.Errorf("failed to get WorkloadPolicy %q in namespace %q: %w", name, namespace, err)
			}

			return policy, nil
		}
	}
}
