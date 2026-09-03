package kubectlplugin

import (
	"bytes"
	"context"
	"fmt"
	"testing"

	securityv1alpha1 "github.com/kubewarden/runtime-enforcer/api/v1alpha1"
	"github.com/kubewarden/runtime-enforcer/internal/types/policymode"
	fakeclient "github.com/kubewarden/runtime-enforcer/pkg/generated/clientset/versioned/fake"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

func TestRunProposalPromote(t *testing.T) {
	t.Parallel()

	const (
		ns   = "test"
		name = "test-deployment"
	)

	tests := []struct {
		name           string
		dryRun         bool
		mode           string
		omitMode       bool
		proposal       *securityv1alpha1.WorkloadPolicyProposal
		policy         *securityv1alpha1.WorkloadPolicy
		expectOutput   string
		expectErr      string
		expectLabel    string
		skipLabelCheck bool
	}{
		{
			name: "promotes proposal and waits for policy",
			mode: policymode.MonitorString,
			proposal: &securityv1alpha1.WorkloadPolicyProposal{
				Name:      name,
				Namespace: ns,
			},
			policy: &securityv1alpha1.WorkloadPolicy{
				Name:      name,
				Namespace: ns,
			},
			expectOutput: fmt.Sprintf(
				"Promoted WorkloadPolicyProposal %q in namespace %q to WorkloadPolicy in %q mode.",
				name,
				ns,
				policymode.MonitorString,
			),
			expectLabel: policymode.MonitorString,
		},
		{
			name: "promotes proposal in protect mode",
			mode: policymode.ProtectString,
			proposal: &securityv1alpha1.WorkloadPolicyProposal{
				Name:      name,
				Namespace: ns,
			},
			policy: &securityv1alpha1.WorkloadPolicy{
				Name:      name,
				Namespace: ns,
			},
			expectOutput: fmt.Sprintf(
				"Promoted WorkloadPolicyProposal %q in namespace %q to WorkloadPolicy in %q mode.",
				name,
				ns,
				policymode.ProtectString,
			),
			expectLabel: policymode.ProtectString,
		},
		{
			name:     "defaults to monitor when mode is omitted",
			omitMode: true,
			proposal: &securityv1alpha1.WorkloadPolicyProposal{
				Name:      name,
				Namespace: ns,
			},
			policy: &securityv1alpha1.WorkloadPolicy{
				Name:      name,
				Namespace: ns,
			},
			expectOutput: fmt.Sprintf(
				"Promoted WorkloadPolicyProposal %q in namespace %q to WorkloadPolicy in %q mode.",
				name,
				ns,
				policymode.MonitorString,
			),
			expectLabel: policymode.MonitorString,
		},
		{
			name:   "dry-run when not yet promoted",
			dryRun: true,
			mode:   policymode.MonitorString,
			proposal: &securityv1alpha1.WorkloadPolicyProposal{
				Name:      name,
				Namespace: ns,
			},
			// In dry-run mode, we don't wait for the policy to be created
			policy: nil,
			expectOutput: fmt.Sprintf(
				"WorkloadPolicyProposal %q in namespace %q can be promoted to WorkloadPolicy in %q mode.",
				name,
				ns,
				policymode.MonitorString,
			),
			expectLabel: policymode.MonitorString,
		},
		{
			name:   "dry-run when already promoted",
			dryRun: true,
			mode:   policymode.MonitorString,
			proposal: &securityv1alpha1.WorkloadPolicyProposal{
				Name:      name,
				Namespace: ns,
				Labels: map[string]string{
					securityv1alpha1.ProposalPromoteLabelKey: policymode.MonitorString,
				},
			},
			expectOutput: fmt.Sprintf(
				"WorkloadPolicyProposal %q in namespace %q is already promoted to WorkloadPolicy.",
				name,
				ns,
			),
			expectLabel: policymode.MonitorString,
		},
		{
			name: "rejects invalid mode",
			mode: "invalid",
			proposal: &securityv1alpha1.WorkloadPolicyProposal{
				Name:      name,
				Namespace: ns,
			},
			expectErr:      `invalid mode "invalid"`,
			skipLabelCheck: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			mode := tt.mode
			if tt.omitMode {
				tf, streams := setupTestFactory(t, tt.proposal.DeepCopy())
				defer tf.Cleanup()

				cmd := newProposalPromoteCmd(commonCmdDeps{f: tf, ioStreams: streams})
				// kubectl runtime-enforcer proposal promote PROPOSAL_NAME (no --mode)
				require.NoError(t, cmd.ParseFlags([]string{}))
				var err error
				mode, err = cmd.Flags().GetString("mode")
				require.NoError(t, err)
				require.Equal(t, policymode.MonitorString, mode)
			}

			securityClient := newProposalPromoteTestClient(tt.proposal, tt.policy).SecurityV1alpha1()

			var out bytes.Buffer
			opts := &proposalPromoteOptions{
				Namespace:    ns,
				DryRun:       tt.dryRun,
				ProposalName: name,
				Mode:         mode,
			}
			ctx, cancel := context.WithTimeout(context.Background(), defaultOperationTimeout)
			defer cancel()

			err := runProposalPromote(ctx, securityClient, opts, &out)
			if tt.expectErr != "" {
				require.Error(t, err)
				require.Contains(t, err.Error(), tt.expectErr)
				return
			}
			require.NoError(t, err)

			wpProposal, err := securityClient.WorkloadPolicyProposals(ns).Get(ctx, name, metav1.GetOptions{})
			require.NoError(t, err)

			// The fake client ignores DryRun and still mutates the object, so we
			// still assert the updated label even in dry-run mode.
			if !tt.skipLabelCheck {
				_, hasPromotionLabel := wpProposal.HasPromotionLabel()
				require.True(t, hasPromotionLabel)
				require.Equal(t, tt.expectLabel, wpProposal.Labels[securityv1alpha1.ProposalPromoteLabelKey])
			}
			require.Contains(t, out.String(), tt.expectOutput)
		})
	}
}

func newProposalPromoteTestClient(
	proposal *securityv1alpha1.WorkloadPolicyProposal,
	policy *securityv1alpha1.WorkloadPolicy,
) *fakeclient.Clientset {
	objects := []runtime.Object{proposal}
	if policy != nil {
		objects = append(objects, policy)
	}

	return fakeclient.NewClientset(objects...)
}

func TestCompleteProposalPromoteArgs(t *testing.T) {
	t.Parallel()
	proposalName := "test-proposal"
	testWorkloadPolicyProposal := &securityv1alpha1.WorkloadPolicyProposal{
		Name: proposalName,
	}

	tf, streams := setupTestFactory(t, testWorkloadPolicyProposal.DeepCopy())
	defer tf.Cleanup()

	cmd := newProposalPromoteCmd(commonCmdDeps{f: tf, ioStreams: streams})
	completes, directive := cmd.ValidArgsFunction(cmd, []string{}, "")
	assert.Equal(t, []string{proposalName}, completes)
	assert.Equal(t, cobra.ShellCompDirectiveNoFileComp, directive)

	modeFlag := cmd.Flags().Lookup("mode")
	require.NotNil(t, modeFlag)
	assert.Equal(t, policymode.MonitorString, modeFlag.DefValue)
}
