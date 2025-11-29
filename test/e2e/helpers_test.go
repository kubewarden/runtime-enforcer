package e2e_test

import (
	"context"
	"testing"
	"time"

	"github.com/neuvector/runtime-enforcer/api/v1alpha1"
	"github.com/stretchr/testify/require"
	"sigs.k8s.io/e2e-framework/klient/k8s"
	"sigs.k8s.io/e2e-framework/klient/k8s/resources"
	"sigs.k8s.io/e2e-framework/klient/wait"
	"sigs.k8s.io/e2e-framework/klient/wait/conditions"
)

func waitForWorkloadPolicyStatusToBeDeployed(
	ctx context.Context,
	t *testing.T,
	policy *v1alpha1.WorkloadSecurityPolicy,
) {
	r := ctx.Value(key("client")).(*resources.Resources)
	const deployedStateStr = string(v1alpha1.DeployedState)
	err := wait.For(conditions.New(r).ResourceMatch(policy, func(obj k8s.Object) bool {
		ps, ok := obj.(*v1alpha1.WorkloadSecurityPolicy)
		if !ok {
			return false
		}
		t.Log("checking workloadsecuritypolicy status:", ps.Status)
		if ps.Status.ObservedGeneration != ps.Generation {
			return false
		}
		if len(ps.Status.Conditions) == 0 {
			return false
		}
		if ps.Status.Conditions[0].Type != deployedStateStr {
			return false
		}
		return ps.Status.State == deployedStateStr
	}), wait.WithTimeout(15*time.Second))
	require.NoError(t, err, "workloadsecuritypolicy status should be updated to Deployed")
}
