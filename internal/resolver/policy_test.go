package resolver

import (
	"testing"

	"github.com/kubewarden/runtime-enforcer/api/v1alpha1"
	agentv1 "github.com/kubewarden/runtime-enforcer/proto/agent/v1"
	"github.com/stretchr/testify/require"
)

const (
	c1   = "c1"
	c2   = "c2"
	c3   = "c3"
	cid1 = "cid1"
	cid2 = "cid2"
	cid3 = "cid3"
)

// TestHandleWP_Lifecycle exercises add → update → delete in one test so the policy is created once.
func TestHandleWP_Lifecycle(t *testing.T) {
	r := NewTestResolver(t)
	wp := &v1alpha1.WorkloadPolicy{
		Name: "example", Namespace: "test-ns",
		Spec: v1alpha1.WorkloadPolicySpec{
			Mode: "monitor",
			RulesByContainer: map[string]*v1alpha1.WorkloadPolicyRules{
				c1: {Executables: v1alpha1.WorkloadPolicyExecutables{Allowed: []string{"/bin/sleep"}}},
				c2: {Executables: v1alpha1.WorkloadPolicyExecutables{Allowed: []string{"/bin/cat"}}},
			},
		},
	}
	key := wp.NamespacedName()

	// A matching pod is required because policy deletion now happens
	// during cgroup detachment, not purely from wpState transitions.
	r.mu.Lock()
	r.podCache["test-pod-uid"] = &podEntry{
		meta: &PodMeta{
			ID:           "test-pod-uid",
			Namespace:    "test-ns",
			Name:         "test-pod",
			WorkloadName: "test",
			WorkloadType: "Deployment",
			Labels:       map[string]string{v1alpha1.PolicyLabelKey: "example"},
		},
		containers: map[ContainerID]*ContainerMeta{
			cid1: {CgroupID: 100, Name: c1, ID: cid1},
			cid2: {CgroupID: 101, Name: c2, ID: cid2},
			cid3: {CgroupID: 102, Name: c3, ID: cid3},
		},
	}
	r.mu.Unlock()

	// Add
	require.NoError(t, r.ReconcileWP(wp))
	require.Contains(t, r.wpState, key)
	state := r.wpState[key]
	require.Len(t, state.polByContainer, 2)
	require.Contains(t, state.polByContainer, c1)
	require.Contains(t, state.polByContainer, c2)
	ids := make(map[PolicyID]struct{})
	for _, id := range state.polByContainer {
		ids[id] = struct{}{}
	}
	require.Equal(t, map[PolicyID]struct{}{PolicyID(1): {}, PolicyID(2): {}}, ids)
	initialState := r.wpState[key]

	statuses := r.GetPolicyStatuses()
	require.Contains(t, statuses, key)
	require.Equal(t, PolicyStatus{
		State:   agentv1.PolicyState_POLICY_STATE_READY,
		Mode:    agentv1.PolicyMode_POLICY_MODE_MONITOR,
		Message: "",
	}, statuses[key])

	// Update: remove c1, update c2 allowed list, add c3
	delete(wp.Spec.RulesByContainer, c1)
	wp.Spec.RulesByContainer[c2] = &v1alpha1.WorkloadPolicyRules{
		Executables: v1alpha1.WorkloadPolicyExecutables{Allowed: []string{"/bin/cat", "/bin/echo"}},
	}
	wp.Spec.RulesByContainer[c3] = &v1alpha1.WorkloadPolicyRules{
		Executables: v1alpha1.WorkloadPolicyExecutables{Allowed: []string{"/bin/ls"}},
	}
	require.NoError(t, r.ReconcileWP(wp))
	state = r.wpState[key]
	require.Len(t, state.polByContainer, 2)
	require.NotContains(t, state.polByContainer, c1)
	require.Equal(t, initialState.polByContainer[c2], state.polByContainer[c2], "c2 keeps its policy ID")
	require.Equal(t, PolicyID(3), state.polByContainer[c3])

	// Delete
	require.NoError(t, r.HandleWPDelete(wp))
	require.NotContains(t, r.wpState, key)
	statuses = r.GetPolicyStatuses()
	require.NotContains(t, statuses, key)
}
