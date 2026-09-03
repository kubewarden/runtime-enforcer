package resolver

import (
	"fmt"
	"maps"

	"github.com/kubewarden/runtime-enforcer/api/v1alpha1"
	"github.com/kubewarden/runtime-enforcer/internal/bpf"
	"github.com/kubewarden/runtime-enforcer/internal/types/policymode"
	agentv1 "github.com/kubewarden/runtime-enforcer/proto/agent/v1"
)

type (
	PolicyID             = uint64
	policyByContainer    = map[ContainerName]PolicyID
	NamespacedPolicyName = string
)

type PolicyStatus struct {
	State   agentv1.PolicyState
	Mode    agentv1.PolicyMode
	Message string
}

type wpInfo struct {
	polByContainer policyByContainer
	status         PolicyStatus
}

const (
	// PolicyIDNone is used to indicate no policy associated with the cgroup.
	PolicyIDNone PolicyID = 0
)

// this must be called with the resolver lock held.
func (r *Resolver) allocPolicyID() PolicyID {
	id := r.nextPolicyID
	r.nextPolicyID++
	return id
}

// upsertPolicyIDInBPF adds or updates all entries for the given policy ID in BPF maps.
// This must be called with the resolver lock held.
func (r *Resolver) upsertPolicyIDInBPF(
	policyID PolicyID,
	allowedBinaries []string,
	mode policymode.Mode,
	valuesOp bpf.PolicyValuesOperation,
) error {
	if err := r.policyUpdateBinariesFunc(policyID, allowedBinaries, valuesOp); err != nil {
		return err
	}
	if err := r.policyModeUpdateFunc(policyID, mode, bpf.UpdateMode); err != nil {
		return err
	}
	return nil
}

// clearPolicyIDFromBPF removes all entries for the given policy ID from BPF maps.
// This must be called with the resolver lock held.
func (r *Resolver) clearPolicyIDFromBPF(policyID PolicyID) error {
	// TODO: refactor the PolicyUpdateBinariesFunc to not collapse the add and replace
	// operations behind the same API. By doing that we will not need to pass a dummy values slice here.
	if err := r.policyUpdateBinariesFunc(policyID, nil, bpf.RemoveValuesFromPolicy); err != nil {
		return err
	}
	// TODO: refactor the PolicyModeUpdateFunc to not collapse the update and delete operations
	// behind the same API. By doing that we will not need to pass a dummy mode value here.
	if err := r.policyModeUpdateFunc(policyID, 0, bpf.DeleteMode); err != nil {
		return err
	}
	return nil
}

// applyPolicyToPod applies the given policy-by-container (add/update) to the pod's cgroups.
// This must be called with the resolver lock held.
func (r *Resolver) applyPolicyToPod(state *podEntry, applied policyByContainer) error {
	for _, container := range state.containers {
		polID, ok := applied[container.Name]
		if !ok {
			// No entry for this container: either not in policy, or unchanged.
			continue
		}
		if err := r.cgroupToPolicyMapUpdateFunc(
			polID,
			[]CgroupID{container.CgroupID},
			bpf.AddPolicyToCgroups,
		); err != nil {
			return fmt.Errorf("failed to add policy to cgroups for pod %s, container %s, policy %s: %w",
				state.podName(), container.Name, state.policyName(), err)
		}
	}
	return nil
}

// removePolicyFromPod removes cgroup→policyID associations for the given containers in the pod.
// It is used to remove policy from containers that are no longer in the spec.
// This must be called with the resolver lock held.
func (r *Resolver) removePolicyFromPod(
	wpKey NamespacedPolicyName,
	podEntry *podEntry,
	wpState, removed policyByContainer,
) error {
	for _, container := range podEntry.containers {
		policyID, ok := removed[container.Name]
		if !ok {
			continue
		}
		if err := r.cgroupToPolicyMapUpdateFunc(
			PolicyIDNone, []CgroupID{container.CgroupID}, bpf.RemoveCgroups,
		); err != nil {
			return fmt.Errorf("failed to remove cgroups for pod %s, container %s, policy %s: %w",
				podEntry.podName(), container.Name, podEntry.policyName(), err)
		}
		if err := r.clearPolicyIDFromBPF(policyID); err != nil {
			return fmt.Errorf("failed to clear policy for wp %s, container %s: %w", wpKey, container.Name, err)
		}
		delete(wpState, container.Name)
	}
	return nil
}

// this must be called with the resolver lock held.
func (r *Resolver) applyPolicyToPodIfPresent(state *podEntry) error {
	policyName := state.policyName()

	// if the pod doesn't have the label we do nothing
	if policyName == "" {
		return nil
	}

	key := fmt.Sprintf("%s/%s", state.podNamespace(), policyName)
	info := r.wpState[key]
	if info == nil {
		// We couldn't find the policy associated to this pod.
		//
		// There are two scenarios that this can happen.
		// - The associated policy is not created at all.
		// - The associated policy is not reconciled yet.
		//
		// Here we only care about the latter, assuming an admission policy or webhook will ensure that the policy always exists.
		// When this happens, we return the error to NRI, so the container would be prevented from starting, depending on related failopen setting.
		return fmt.Errorf(
			"pod '%s/%s' has policy '%s' associated, but the policy does not exist",
			state.podNamespace(),
			state.podName(),
			policyName,
		)
	}

	return r.applyPolicyToPod(state, info.polByContainer)
}

// syncWorkloadPolicy ensures state and BPF maps match wp.Spec.RulesByContainer:
// allocates a policy ID for new containers, (re)applies binaries and mode for every container in the spec.
// It returns the container→policyID map for newly created policy IDs.
// This must be called with the resolver lock held.
func (r *Resolver) syncWorkloadPolicy(wp *v1alpha1.WorkloadPolicy) (policyByContainer, error) {
	wpKey := wp.NamespacedName()
	mode := policymode.ParseMode(wp.Spec.Mode)
	// info is not nil. The caller must ensure the policy exists in wpState before calling.
	info := r.wpState[wpKey]
	newContainers := make(policyByContainer)

	for containerName, containerRules := range wp.Spec.RulesByContainer {
		polID, hadPolicyID := info.polByContainer[containerName]
		op := bpf.ReplaceValuesInPolicy
		if !hadPolicyID {
			polID = r.allocPolicyID()
			newContainers[containerName] = polID
			r.logger.Info("create container policy", "id", polID,
				"wp", wpKey,
				"container", containerName)
			op = bpf.AddValuesToPolicy
		}
		if err := r.upsertPolicyIDInBPF(polID, containerRules.Executables.Allowed, mode, op); err != nil {
			return nil, fmt.Errorf("failed to populate policy for wp %s, container %s: %w", wpKey, containerName, err)
		}
	}

	return newContainers, nil
}

// ReconcileWP enforces the workload policy from the current spec, removes containers
// that are no longer in the spec, then applies policy to all matching pods.
func (r *Resolver) ReconcileWP(wp *v1alpha1.WorkloadPolicy) error {
	r.logger.Info(
		"reconcile wp-policy",
		"wp", wp.NamespacedName(),
		"mode", wp.Spec.Mode,
	)
	r.mu.Lock()

	var info *wpInfo
	var err error
	mode := policymode.ParsePolicyModeToProto(wp.Spec.Mode)
	defer func() {
		if err != nil && info != nil {
			info.setPolicyStatus(agentv1.PolicyState_POLICY_STATE_ERROR, mode, err.Error())
		}
		r.mu.Unlock()
	}()

	wpKey := wp.NamespacedName()
	info = r.wpState[wpKey]
	if info == nil {
		info = &wpInfo{polByContainer: make(policyByContainer, len(wp.Spec.RulesByContainer))}
		r.wpState[wpKey] = info
	}

	var newContainers policyByContainer
	if newContainers, err = r.syncWorkloadPolicy(wp); err != nil {
		return err
	}
	maps.Copy(info.polByContainer, newContainers)

	// Split state into applied (still in spec) vs removed (no longer in spec).
	appliedMap := make(policyByContainer, len(wp.Spec.RulesByContainer))
	removedMap := make(policyByContainer, len(info.polByContainer))
	for containerName := range info.polByContainer {
		if _, stillPresent := wp.Spec.RulesByContainer[containerName]; stillPresent {
			appliedMap[containerName] = info.polByContainer[containerName]
		} else {
			removedMap[containerName] = info.polByContainer[containerName]
		}
	}

	for _, podEntry := range r.podCache {
		if !podEntry.matchPolicy(wp.Name, wp.Namespace) {
			continue
		}
		if err = r.removePolicyFromPod(wpKey, podEntry, info.polByContainer, removedMap); err != nil {
			return err
		}
		if err = r.applyPolicyToPod(podEntry, appliedMap); err != nil {
			return err
		}
	}
	info.setPolicyStatus(agentv1.PolicyState_POLICY_STATE_READY, mode, "")
	return nil
}

// HandleWPDelete removes a workload policy from the resolver cache and updates the BPF maps accordingly.
func (r *Resolver) HandleWPDelete(wp *v1alpha1.WorkloadPolicy) error {
	r.logger.Info(
		"delete-wp-policy",
		"wp", wp.NamespacedName(),
	)
	r.mu.Lock()
	defer r.mu.Unlock()

	wpKey := wp.NamespacedName()
	info := r.wpState[wpKey]
	if info == nil {
		r.logger.Warn(
			"a workload policy is being deleted but the item is not in the resolver cache",
			"policy",
			wp.NamespacedName(),
		)
		return nil
	}
	delete(r.wpState, wpKey)

	for containerName, policyID := range info.polByContainer {
		// First we remove the association cgroupID -> PolicyID and then we will remove the policy values and modes

		// iteration + deletion on the ebpf map
		if err := r.cgroupToPolicyMapUpdateFunc(policyID, []CgroupID{}, bpf.RemovePolicy); err != nil {
			return fmt.Errorf("failed to remove policy from cgroup map: %w", err)
		}
		if err := r.clearPolicyIDFromBPF(policyID); err != nil {
			return fmt.Errorf("failed to clear policy for wp %s, container %s: %w", wpKey, containerName, err)
		}
	}
	return nil
}

// GetPolicyStatuses returns the current policy statuses keyed by namespaced name (e.g. "namespace/name").
func (r *Resolver) GetPolicyStatuses() map[NamespacedPolicyName]PolicyStatus {
	r.mu.Lock()
	defer r.mu.Unlock()

	statuses := make(map[NamespacedPolicyName]PolicyStatus, len(r.wpState))
	for k, v := range r.wpState {
		if v != nil {
			statuses[k] = v.status
		}
	}
	return statuses
}

func (i *wpInfo) setPolicyStatus(state agentv1.PolicyState, mode agentv1.PolicyMode, message string) {
	i.status = PolicyStatus{
		State:   state,
		Mode:    mode,
		Message: message,
	}
}
