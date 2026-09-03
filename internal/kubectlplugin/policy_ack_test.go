package kubectlplugin

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/kubewarden/runtime-enforcer/api/v1alpha1"
	fakeclient "github.com/kubewarden/runtime-enforcer/pkg/generated/clientset/versioned/fake"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestRunPolicyAck(t *testing.T) {
	t.Parallel()

	const (
		ns   = "test"
		name = "test-policy"
	)

	makePolicy := func(annotations map[string]string) *v1alpha1.WorkloadPolicy {
		return &v1alpha1.WorkloadPolicy{
			Name:        name,
			Namespace:   ns,
			Annotations: annotations,
			Status: v1alpha1.WorkloadPolicyStatus{
				Violations: []v1alpha1.ViolationRecord{
					{
						ID:             1,
						ContainerName:  "app",
						ExecutablePath: "/bin/mv",
						PodName:        "app-pod",
					},
					{
						ID:             2,
						ContainerName:  "app",
						ExecutablePath: "/bin/cat",
						PodName:        "app-pod",
					},
				},
			},
		}
	}

	tests := []struct {
		name           string
		policy         *v1alpha1.WorkloadPolicy
		violationID    int64
		reason         string
		reasonSet      bool
		dryRun         bool
		stdin          string
		expectErrSub   string
		expectMsgSub   string
		expectAnnotKey string
		expectAnnotVal string
	}{
		{
			name:           "ack_with_reason_flag",
			policy:         makePolicy(nil),
			violationID:    1,
			reason:         "ongoing incident",
			reasonSet:      true,
			expectMsgSub:   "Successfully acknowledged violation 1",
			expectAnnotKey: violationAcknowledgeAnnotationKey(1),
			expectAnnotVal: "ongoing incident",
		},
		{
			name:         "ack_with_empty_reason_flag",
			policy:       makePolicy(nil),
			violationID:  1,
			reason:       "",
			reasonSet:    true,
			expectErrSub: "acknowledgement reason is required",
		},
		{
			name:         "ack_with_whitespace_reason_flag",
			policy:       makePolicy(nil),
			violationID:  1,
			reason:       "   ",
			reasonSet:    true,
			expectErrSub: "acknowledgement reason is required",
		},
		{
			name:         "ack_empty_prompt",
			policy:       makePolicy(nil),
			violationID:  1,
			reasonSet:    false,
			stdin:        "\n",
			expectErrSub: "acknowledgement reason is required",
		},
		{
			name:           "ack_prompted_reason",
			policy:         makePolicy(nil),
			violationID:    2,
			reasonSet:      false,
			stdin:          "manual triage\n",
			expectMsgSub:   "Successfully acknowledged violation 2",
			expectAnnotKey: violationAcknowledgeAnnotationKey(2),
			expectAnnotVal: "manual triage",
		},
		{
			name:           "ack_dry_run",
			policy:         makePolicy(nil),
			violationID:    1,
			reason:         "dry run reason",
			reasonSet:      true,
			dryRun:         true,
			expectMsgSub:   "Would acknowledge violation 1",
			expectAnnotKey: violationAcknowledgeAnnotationKey(1),
			expectAnnotVal: "dry run reason",
		},
		{
			name:         "unknown_violation_id",
			policy:       makePolicy(nil),
			violationID:  99,
			reason:       "ignored",
			reasonSet:    true,
			expectErrSub: "violation id 99 not found in status.violations",
		},
		{
			name: "noop_same_annotation",
			policy: makePolicy(map[string]string{
				violationAcknowledgeAnnotationKey(1): "already set",
			}),
			violationID:    1,
			reason:         "already set",
			reasonSet:      true,
			expectMsgSub:   "No changes required",
			expectAnnotKey: violationAcknowledgeAnnotationKey(1),
			expectAnnotVal: "already set",
		},
		{
			name: "overwrite_different_reason",
			policy: makePolicy(map[string]string{
				violationAcknowledgeAnnotationKey(1): "old reason",
			}),
			violationID:    1,
			reason:         "new reason",
			reasonSet:      true,
			expectMsgSub:   "Successfully acknowledged violation 1",
			expectAnnotKey: violationAcknowledgeAnnotationKey(1),
			expectAnnotVal: "new reason",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			clientset := fakeclient.NewClientset(tt.policy.DeepCopy())
			securityClient := clientset.SecurityV1alpha1()

			var out, errOut bytes.Buffer
			opts := &policyAckOptions{
				Namespace:   ns,
				DryRun:      tt.dryRun,
				PolicyName:  name,
				ViolationID: tt.violationID,
				Reason:      tt.reason,
				reasonSet:   tt.reasonSet,
			}

			ctx, cancel := context.WithTimeout(context.Background(), defaultOperationTimeout)
			defer cancel()

			err := runPolicyAck(ctx, securityClient, opts, strings.NewReader(tt.stdin), &out, &errOut)
			if tt.expectErrSub != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectErrSub)
				return
			}
			require.NoError(t, err)
			require.Contains(t, out.String(), tt.expectMsgSub)

			updatedPolicy, err := securityClient.WorkloadPolicies(ns).Get(ctx, name, metav1.GetOptions{})
			require.NoError(t, err)
			require.Equal(t, tt.expectAnnotVal, updatedPolicy.Annotations[tt.expectAnnotKey])
		})
	}
}

func TestCompletePolicyAckValidArgs(t *testing.T) {
	t.Parallel()

	testWorkloadPolicy := &v1alpha1.WorkloadPolicy{
		Name:      "test-policy",
		Namespace: "test",
		Status: v1alpha1.WorkloadPolicyStatus{
			Violations: []v1alpha1.ViolationRecord{
				{ID: 1, ContainerName: "app", ExecutablePath: "/bin/mv"},
				{ID: 2, ContainerName: "app", ExecutablePath: "/bin/ls"},
			},
		},
	}

	emptyWorkloadPolicy := &v1alpha1.WorkloadPolicy{
		Name:      "test-policy",
		Namespace: "test",
		Status:    v1alpha1.WorkloadPolicyStatus{},
	}

	tests := []struct {
		name              string
		policy            *v1alpha1.WorkloadPolicy
		args              []string
		expectedCompletes []string
	}{
		// policy name completion: `kubectl runtime-enforcer policy ack [TAB]`
		{
			name:              "policy names",
			policy:            testWorkloadPolicy,
			args:              []string{},
			expectedCompletes: []string{"test-policy"},
		},
		// violation id completion: `kubectl runtime-enforcer policy ack test-policy [TAB]`
		{
			name:              "violation ids",
			policy:            testWorkloadPolicy,
			args:              []string{"test-policy"},
			expectedCompletes: []string{"1\t/bin/mv", "2\t/bin/ls"},
		},
		{
			name:              "no violation ids from empty policy",
			policy:            emptyWorkloadPolicy,
			args:              []string{"test-policy"},
			expectedCompletes: nil,
		},
		// no further positional args: `kubectl runtime-enforcer policy ack test-policy 1 [TAB]`
		{
			name:              "no completions after both args",
			policy:            testWorkloadPolicy,
			args:              []string{"test-policy", "1"},
			expectedCompletes: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			tf, streams := setupTestFactory(t, tt.policy.DeepCopy())
			defer tf.Cleanup()

			cmd := newPolicyAckCmd(commonCmdDeps{f: tf, ioStreams: streams})
			completes, directive := cmd.ValidArgsFunction(cmd, tt.args, "")
			assert.Equal(t, tt.expectedCompletes, completes)
			assert.Equal(t, cobra.ShellCompDirectiveNoFileComp, directive)
		})
	}
}
