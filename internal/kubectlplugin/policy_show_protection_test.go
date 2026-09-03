package kubectlplugin

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/kubewarden/runtime-enforcer/api/v1alpha1"
	"github.com/kubewarden/runtime-enforcer/internal/types/policymode"
	"github.com/kubewarden/runtime-enforcer/internal/types/workloadkind"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
)

const (
	podTemplateHashLabel = "pod-template-hash"
	policyName           = "test-policy"
)

func TestValidatePolicyShowProtectionOutput(t *testing.T) {
	t.Parallel()
	var out bytes.Buffer
	require.NoError(t, renderPolicyProtection(policyShowProtectionOutputTable, &out, nil))
	require.NoError(t, renderPolicyProtection(policyShowProtectionOutputJSON, &out, nil))
	require.Error(t, renderPolicyProtection("yaml", &out, nil))
}

func TestBuildWorkloadProtectionRows(t *testing.T) {
	t.Parallel()

	namespaceA := "ns-a"
	namespaceB := "ns-b"

	tests := []struct {
		name     string
		pods     []corev1.Pod
		policies []v1alpha1.WorkloadPolicy
		expected []workloadProtectionRow
	}{
		{
			name: "group deployment pods into one workload row",
			pods: []corev1.Pod{
				{
					Name:      "opensuse-deployment-6469c647b5-2ftx7",
					Namespace: namespaceA,
					Labels: map[string]string{
						v1alpha1.PolicyLabelKey: policyName,
						podTemplateHashLabel:    "6469c647b5",
					},
				},
				{
					Name:      "opensuse-deployment-6469c647b5-tjssz",
					Namespace: namespaceA,
					Labels: map[string]string{
						v1alpha1.PolicyLabelKey: policyName,
						podTemplateHashLabel:    "6469c647b5",
					},
				},
			},
			policies: []v1alpha1.WorkloadPolicy{
				{
					Name: policyName, Namespace: namespaceA,
					Spec:   v1alpha1.WorkloadPolicySpec{Mode: policymode.ProtectString},
					Status: v1alpha1.WorkloadPolicyStatus{Phase: v1alpha1.Ready},
				},
			},
			expected: []workloadProtectionRow{
				{
					Workload: types.NamespacedName{Namespace: namespaceA, Name: "opensuse-deployment"}.String(),
					Kind:     workloadkind.Deployment.String(),
					Policy:   policyName,
					Mode:     modeToUpper(policymode.ProtectString),
					Status:   string(v1alpha1.Ready),
				},
			},
		},
		{
			name: "missing policy uses unknown mode and missing status",
			pods: []corev1.Pod{
				{
					Name:      "opensuse-deployment-6469c647b5-2ftx7",
					Namespace: namespaceA,
					Labels: map[string]string{
						v1alpha1.PolicyLabelKey: policyName,
						podTemplateHashLabel:    "6469c647b5",
					},
				},
			},
			policies: nil,
			expected: []workloadProtectionRow{
				{
					Workload: types.NamespacedName{Namespace: namespaceA, Name: "opensuse-deployment"}.String(),
					Kind:     workloadkind.Deployment.String(),
					Policy:   policyName,
					Mode:     unknownMode,
					Status:   missingStatus,
				},
			},
		},
		{
			name: "same policy name in different namespaces respects namespace",
			pods: []corev1.Pod{
				{
					Name:      "pod-a",
					Namespace: namespaceA,
					Labels: map[string]string{
						v1alpha1.PolicyLabelKey: policyName,
					},
				},
				{
					Name:      "pod-b",
					Namespace: namespaceB,
					Labels: map[string]string{
						v1alpha1.PolicyLabelKey: policyName,
					},
				},
			},
			policies: []v1alpha1.WorkloadPolicy{
				{
					Name: policyName, Namespace: namespaceA,
					Spec:   v1alpha1.WorkloadPolicySpec{Mode: policymode.MonitorString},
					Status: v1alpha1.WorkloadPolicyStatus{Phase: v1alpha1.Ready},
				},
				{
					Name: policyName, Namespace: namespaceB,
					Spec:   v1alpha1.WorkloadPolicySpec{Mode: policymode.ProtectString},
					Status: v1alpha1.WorkloadPolicyStatus{Phase: v1alpha1.Failed},
				},
			},
			expected: []workloadProtectionRow{
				{
					Workload: types.NamespacedName{Namespace: namespaceA, Name: "pod-a"}.String(),
					Kind:     workloadkind.Pod.String(),
					Policy:   policyName,
					Mode:     modeToUpper(policymode.MonitorString),
					Status:   string(v1alpha1.Ready),
				},
				{
					Workload: types.NamespacedName{Namespace: namespaceB, Name: "pod-b"}.String(),
					Kind:     workloadkind.Pod.String(),
					Policy:   policyName,
					Mode:     modeToUpper(policymode.ProtectString),
					Status:   string(v1alpha1.Failed),
				},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			rows := buildWorkloadProtectionRows(tc.pods, tc.policies)
			require.Equal(t, tc.expected, rows)
		})
	}
}

func TestRenderPolicyProtection(t *testing.T) {
	t.Parallel()

	workloadName := "ns-a/opensuse-deployment"
	rows := []workloadProtectionRow{{
		Workload: workloadName,
		Kind:     workloadkind.Deployment.String(),
		Policy:   policyName,
		Mode:     modeToUpper(policymode.ProtectString),
		Status:   string(v1alpha1.Ready),
	}}

	t.Run("validate json", func(t *testing.T) {
		t.Parallel()
		var out bytes.Buffer
		err := renderPolicyProtectionJSON(&out, rows)
		require.NoError(t, err)

		var decoded []map[string]any
		require.NoError(t, json.Unmarshal(out.Bytes(), &decoded))
		require.Len(t, decoded, 1)
		require.Equal(t, workloadName, decoded[0]["workload"])
		require.Equal(t, policyName, decoded[0]["policy"])
		require.Equal(t, workloadkind.Deployment.String(), decoded[0]["kind"])
		require.Equal(t, modeToUpper(policymode.ProtectString), decoded[0]["mode"])
		require.Equal(t, string(v1alpha1.Ready), decoded[0]["status"])
	})

	t.Run("validate table", func(t *testing.T) {
		t.Parallel()
		var out bytes.Buffer
		err := renderPolicyProtectionTable(&out, rows)
		require.NoError(t, err)

		output := out.String()
		require.Contains(t, output, "WORKLOAD")
		require.Contains(t, output, "KIND")
		require.Contains(t, output, "POLICY")
		require.Contains(t, output, "MODE")
		require.Contains(t, output, "STATUS")
		require.Contains(t, output, workloadName)
		require.Contains(t, output, policyName)
		require.Contains(t, output, workloadkind.Deployment.String())
		require.Contains(t, output, modeToUpper(policymode.ProtectString))
		require.Contains(t, output, string(v1alpha1.Ready))
	})
}
