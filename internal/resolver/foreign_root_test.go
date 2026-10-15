package resolver

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/kubewarden/runtime-enforcer/api/v1alpha1"
	"github.com/kubewarden/runtime-enforcer/internal/bpf"
	"github.com/kubewarden/runtime-enforcer/internal/testutil"
	"github.com/kubewarden/runtime-enforcer/internal/types/policymode"
)

// TestReconcileWP_AllowForeignRootExec checks the per-container
// allowForeignRootExec flag. The test confirms that the resolver passes the flag
// from the WorkloadPolicy spec to the BPF update function. The BPF update
// function uses the policy ID of the container as the key. The test also confirms
// that the resolver clears the flag when it removes the container from the policy.
func TestReconcileWP_AllowForeignRootExec(t *testing.T) {
	type settingsCall struct {
		allow bool
		op    bpf.PolicySettingsOperation
	}
	settingsCalls := make(map[PolicyID]settingsCall)

	r, err := NewResolver(
		testutil.NewTestLogger(t),
		func(_ uint64, _ string) error { return nil },
		func(_ PolicyID, _ []CgroupID, _ bpf.CgroupPolicyOperation) error { return nil },
		func(_ PolicyID, _ []string, _ bpf.PolicyValuesOperation) error { return nil },
		func(policyID PolicyID, _ policymode.Mode, allow bool, op bpf.PolicySettingsOperation) error {
			settingsCalls[policyID] = settingsCall{allow: allow, op: op}
			return nil
		},
	)
	require.NoError(t, err)

	wp := &v1alpha1.WorkloadPolicy{
		Name: "example", Namespace: "test-ns",
		Spec: v1alpha1.WorkloadPolicySpec{
			Mode: "protect",
			RulesByContainer: map[string]*v1alpha1.WorkloadPolicyRules{
				c1: {
					Executables: v1alpha1.WorkloadPolicyExecutables{Allowed: []string{"/service"}},
					Options:     map[string]string{v1alpha1.OptionAllowForeignRootExec: "1"},
				},
				c2: {
					Executables: v1alpha1.WorkloadPolicyExecutables{Allowed: []string{"/bin/cat"}},
					Options:     map[string]string{"SOME_REMOVED_FLAG": "1"},
				},
			},
		},
	}
	key := wp.NamespacedName()

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
		},
	}
	r.mu.Unlock()

	require.NoError(t, r.ReconcileWP(wp))

	state := r.wpState[key]
	polC1 := state.polByContainer[c1]
	polC2 := state.polByContainer[c2]

	require.Equal(t, settingsCall{allow: true, op: bpf.UpdateSettings}, settingsCalls[polC1],
		"container opting in must enable foreign-root execs")
	require.Equal(t, settingsCall{allow: false, op: bpf.UpdateSettings}, settingsCalls[polC2],
		"container without the flag, with only an unknown option key, must be blocked by default")

	// When the test removes c1 from the spec, the resolver must delete the
	// foreign-root entry of c1.
	delete(wp.Spec.RulesByContainer, c1)
	require.NoError(t, r.ReconcileWP(wp))
	require.Equal(t, bpf.DeleteSettings, settingsCalls[polC1].op,
		"removed container must have its settings entry deleted")
}
