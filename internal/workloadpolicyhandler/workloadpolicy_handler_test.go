package workloadpolicyhandler_test

import (
	"log/slog"
	"os"
	"testing"

	"github.com/kubewarden/runtime-enforcer/api/v1alpha1"
	"github.com/kubewarden/runtime-enforcer/internal/resolver"
	"github.com/kubewarden/runtime-enforcer/internal/workloadpolicyhandler"
	agentv1 "github.com/kubewarden/runtime-enforcer/proto/agent/v1"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

func TestWorkloadPolicyHandler(t *testing.T) {
	const policyName = "test-policy"
	const testNamespace = "default"

	typeNamespacedName := types.NamespacedName{
		Name:      policyName,
		Namespace: testNamespace,
	}

	policy := &v1alpha1.WorkloadPolicy{
		Name:      policyName,
		Namespace: testNamespace,
		Spec: v1alpha1.WorkloadPolicySpec{
			Mode: "monitor",
			RulesByContainer: map[string]*v1alpha1.WorkloadPolicyRules{
				"main": {
					Executables: v1alpha1.WorkloadPolicyExecutables{
						Allowed: []string{"/usr/bin/sleep"},
					},
				},
			},
		},
	}
	scheme := runtime.NewScheme()
	v1alpha1.AddToScheme(scheme)
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(policy).Build()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	resolver := resolver.NewTestResolver(t)

	wpHandler := workloadpolicyhandler.NewWorkloadPolicyHandler(
		fakeClient,
		logger,
		resolver,
	)

	// 1. reconcile a wp and verify the status is updated to ready
	_, err := wpHandler.Reconcile(t.Context(), reconcile.Request{
		NamespacedName: typeNamespacedName,
	})
	require.NoError(t, err)

	policyStatus := resolver.GetPolicyStatuses()
	require.NotNil(t, policyStatus)

	status, exists := policyStatus[policy.NamespacedName()]
	require.True(t, exists)
	require.Equal(t, agentv1.PolicyState_POLICY_STATE_READY, status.State)
	require.Equal(t, agentv1.PolicyMode_POLICY_MODE_MONITOR, status.Mode)

	// 2. delete the wp and verify the status is removed
	err = fakeClient.Delete(t.Context(), &v1alpha1.WorkloadPolicy{
		Name:      typeNamespacedName.Name,
		Namespace: typeNamespacedName.Namespace,
	},
	)

	require.NoError(t, err)
	err = fakeClient.Get(t.Context(), typeNamespacedName, &v1alpha1.WorkloadPolicy{})
	require.Error(t, err)

	// Reconcile again to trigger the deletion handling logic.
	_, err = wpHandler.Reconcile(t.Context(), reconcile.Request{
		NamespacedName: typeNamespacedName,
	})
	require.NoError(t, err)

	policyStatus = resolver.GetPolicyStatuses()
	require.NotNil(t, policyStatus)

	_, exists = policyStatus[policy.NamespacedName()]
	require.False(t, exists)
}
