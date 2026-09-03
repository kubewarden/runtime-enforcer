package kubectlplugin

import (
	"bytes"
	"context"
	"testing"

	"github.com/kubewarden/runtime-enforcer/api/v1alpha1"
	fakeclient "github.com/kubewarden/runtime-enforcer/pkg/generated/clientset/versioned/fake"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestRunPolicyExec(t *testing.T) {
	t.Parallel()

	const (
		ns            = "test"
		name          = "test-policy"
		containerName = "app"
	)

	tests := []struct {
		name         string
		action       policyExecAction
		dryRun       bool
		initialList  []string
		executables  []string
		expectedList []string
		expectMsgSub string
	}{
		{
			name:         "allow_add_multiple",
			action:       policyExecActionAllow,
			dryRun:       false,
			initialList:  []string{"/bin/ls"},
			executables:  []string{"/bin/mv", "/bin/cat"},
			expectedList: []string{"/bin/ls", "/bin/mv", "/bin/cat"},
			expectMsgSub: "Successfully updated executables",
		},
		{
			name:         "deny_remove_one",
			action:       policyExecActionDeny,
			dryRun:       false,
			initialList:  []string{"/bin/ls", "/bin/mv", "/bin/cat"},
			executables:  []string{"/bin/mv"},
			expectedList: []string{"/bin/ls", "/bin/cat"},
			expectMsgSub: "Successfully updated executables",
		},
		{
			name:         "allow_dry_run",
			action:       policyExecActionAllow,
			dryRun:       true,
			initialList:  []string{"/bin/ls"},
			executables:  []string{"/bin/mv", "/bin/cat"},
			expectedList: []string{"/bin/ls", "/bin/mv", "/bin/cat"},
			expectMsgSub: "Would allow executables for WorkloadPolicy",
		},
		{
			name:         "deny_dry_run",
			action:       policyExecActionDeny,
			dryRun:       true,
			initialList:  []string{"/bin/ls", "/bin/mv", "/bin/cat"},
			executables:  []string{"/bin/mv"},
			expectedList: []string{"/bin/ls", "/bin/cat"},
			expectMsgSub: "Would deny executables for WorkloadPolicy",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			policy := &v1alpha1.WorkloadPolicy{
				Name:      name,
				Namespace: ns,
				Spec: v1alpha1.WorkloadPolicySpec{
					RulesByContainer: map[string]*v1alpha1.WorkloadPolicyRules{
						"app": {
							Executables: v1alpha1.WorkloadPolicyExecutables{
								Allowed: append([]string(nil), tt.initialList...),
							},
						},
					},
				},
			}

			clientset := fakeclient.NewClientset(policy)
			securityClient := clientset.SecurityV1alpha1()

			var out bytes.Buffer
			opts := &policyExecOptions{
				Namespace:     ns,
				DryRun:        tt.dryRun,
				PolicyName:    name,
				ContainerName: containerName,
				Executables:   tt.executables,
				Action:        tt.action,
			}

			ctx, cancel := context.WithTimeout(context.Background(), defaultOperationTimeout)
			defer cancel()

			err := runPolicyExec(ctx, securityClient, opts, &out)
			require.NoError(t, err)

			output := out.String()
			require.Contains(t, output, tt.expectMsgSub)

			updatedPolicy, err := securityClient.WorkloadPolicies(ns).Get(ctx, name, metav1.GetOptions{})
			require.NoError(t, err)

			rules := updatedPolicy.Spec.RulesByContainer[containerName]
			require.NotNil(t, rules)
			require.ElementsMatch(t, tt.expectedList, rules.Executables.Allowed)
		})
	}
}

func TestCompletePolicyExecValidArgs(t *testing.T) {
	t.Parallel()

	testWorkloadPolicy := &v1alpha1.WorkloadPolicy{
		Name:      "test-policy",
		Namespace: "test",
		Spec: v1alpha1.WorkloadPolicySpec{
			RulesByContainer: map[string]*v1alpha1.WorkloadPolicyRules{
				"app": {
					Executables: v1alpha1.WorkloadPolicyExecutables{
						Allowed: []string{"/bin/ls", "/bin/cat"},
					},
				},
				"db": {
					Executables: v1alpha1.WorkloadPolicyExecutables{
						Allowed: []string{"/bin/ps", "/bin/top"},
					},
				},
			},
		},
		Status: v1alpha1.WorkloadPolicyStatus{
			ObservedGeneration: 1,
			Violations: []v1alpha1.ViolationRecord{
				{
					ContainerName:  "app",
					ExecutablePath: "/bin/mv",
				},
				{
					ContainerName:  "app",
					ExecutablePath: "/bin/ls",
				},
			},
		},
	}

	emptyWorkloadPolicy := &v1alpha1.WorkloadPolicy{
		Name:      "test-policy",
		Namespace: "test",
		Spec:      v1alpha1.WorkloadPolicySpec{},
		Status:    v1alpha1.WorkloadPolicyStatus{},
	}

	tests := []struct {
		name              string
		action            policyExecAction
		policy            *v1alpha1.WorkloadPolicy
		args              []string
		expectedCompletes []string
	}{
		// policy name completion: `kubectl runtime-enforcer policy allow|deny [TAB]`
		{
			name:              "policy names for allow action",
			action:            policyExecActionAllow,
			policy:            testWorkloadPolicy,
			args:              []string{},
			expectedCompletes: []string{"test-policy"},
		},
		{
			name:              "policy names for deny action",
			action:            policyExecActionDeny,
			policy:            testWorkloadPolicy,
			args:              []string{},
			expectedCompletes: []string{"test-policy"},
		},
		// container name completion: `kubectl runtime-enforcer policy allow|deny test-policy [TAB]`
		{
			name:              "container names for allow action",
			action:            policyExecActionAllow,
			policy:            testWorkloadPolicy,
			args:              []string{"test-policy"},
			expectedCompletes: []string{"app", "db"},
		},
		{
			name:              "container names for deny action",
			action:            policyExecActionDeny,
			policy:            testWorkloadPolicy,
			args:              []string{"test-policy"},
			expectedCompletes: []string{"app", "db"},
		},
		// executable path completion: `kubectl runtime-enforcer policy allow test-policy app [TAB]`
		// allow: options come from the policy status (observed violations)
		// deny:  options come from the existing allow rules
		{
			name:              "executable paths for allow action",
			action:            policyExecActionAllow,
			policy:            testWorkloadPolicy,
			args:              []string{"test-policy", "app"},
			expectedCompletes: []string{"/bin/mv", "/bin/ls"},
		},
		{
			name:              "executable paths for deny action",
			action:            policyExecActionDeny,
			policy:            testWorkloadPolicy,
			args:              []string{"test-policy", "app"},
			expectedCompletes: []string{"/bin/ls", "/bin/cat"},
		},

		// Forced errors from empty policy
		{
			name:              "forced error: container names for allow action from empty policy",
			action:            policyExecActionAllow,
			policy:            emptyWorkloadPolicy,
			args:              []string{"test-policy"},
			expectedCompletes: nil,
		},
		{
			name:              "forced error: container names for deny action from empty policy",
			action:            policyExecActionDeny,
			policy:            emptyWorkloadPolicy,
			args:              []string{"test-policy"},
			expectedCompletes: nil,
		},
		// executable path completion: `kubectl runtime-enforcer policy allow test-policy app [TAB]`
		// allow: options come from the policy status (observed violations)
		// deny:  options come from the existing allow rules
		{
			name:              "forced error: executable paths for allow action from empty policy",
			action:            policyExecActionAllow,
			policy:            emptyWorkloadPolicy,
			args:              []string{"test-policy", "app"},
			expectedCompletes: nil,
		},
		{
			name:              "forced error: executable paths for deny action from empty policy",
			action:            policyExecActionDeny,
			policy:            emptyWorkloadPolicy,
			args:              []string{"test-policy", "app"},
			expectedCompletes: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			tf, streams := setupTestFactory(t, tt.policy.DeepCopy())
			defer tf.Cleanup()

			cmd := newPolicyExecCmd(commonCmdDeps{f: tf, ioStreams: streams}, tt.action)
			completes, directive := cmd.ValidArgsFunction(cmd, tt.args, "")
			assert.Equal(t, tt.expectedCompletes, completes)
			assert.Equal(t, cobra.ShellCompDirectiveNoFileComp, directive)
		})
	}
}
