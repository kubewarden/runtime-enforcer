package resolver

import (
	"fmt"
	"log/slog"

	"github.com/neuvector/runtime-enforcer/api/v1alpha1"
	"github.com/neuvector/runtime-enforcer/internal/bpf"
	"github.com/neuvector/runtime-enforcer/internal/types/policymode"
	"k8s.io/client-go/tools/cache"
)

type PolicyID = uint64

const (
	// PolicyIDNone is used to indicate no policy associated with the cgroup.
	PolicyIDNone PolicyID = 0
)

func (r *Resolver) allocPolicyID() PolicyID {
	id := r.nextPolicyID
	r.nextPolicyID++
	return id
}

// this must be called with the resolver lock held.
func (r *Resolver) applyPolicyToPod(state *podState, wp map[string]PolicyID) error {
	for _, container := range state.containers {
		polID, ok := wp[container.name]
		if !ok {
			r.logger.Error("container unprotected",
				"pod name", state.podName(),
				"wp", state.policyLabel(),
				"container", container.name)
			continue
		}
		if err := r.cgroupToPolicyMapUpdateFunc(polID, []CgroupID{container.cgID}, bpf.AddPolicyToCgroups); err != nil {
			return fmt.Errorf("failed to update cgroup to policy map for pod %s, container %s, wp %s: %w",
				state.podName(), container.name, state.policyLabel(), err)
		}
	}
	return nil
}

// this must be called with the resolver lock held.
func (r *Resolver) applyPolicyToPodIfPresent(state *podState) error {
	policyName := state.policyLabel()

	// if the policy doesn't have the label we do nothing
	if policyName == "" {
		return nil
	}

	key := fmt.Sprintf("%s/%s", state.podNamespace(), policyName)
	pol, ok := r.wpState[key]
	if !ok {
		return fmt.Errorf(
			"pod has policy label but policy does not exist. pod-name: %s, pod-namespace: %s, policy-name: %s",
			state.podName(),
			state.podNamespace(),
			policyName,
		)
	}

	return r.applyPolicyToPod(state, pol)
}

func (r *Resolver) addWP(wp *v1alpha1.WorkloadPolicy) error {
	r.logger.Info(
		"add-wp-policy",
		"policy-name", wp.Name,
		"policy-namespace", wp.Namespace,
	)
	r.mu.Lock()
	defer r.mu.Unlock()

	// the key is namespace + / + policyName
	wpKey := wp.Namespace + "/" + wp.Name
	if _, exists := r.wpState[wpKey]; exists {
		return fmt.Errorf("workload policy already exists in internal state: %s", wpKey)
	}

	r.wpState[wpKey] = make(map[string]PolicyID, len(wp.Spec.RulesByContainer))

	for containerName, containerRules := range wp.Spec.RulesByContainer {
		polID := r.allocPolicyID()
		r.logger.Info("create policy", "id", polID,
			"wp", wpKey,
			"container", containerName)

		// Populate policy values
		if err := r.policyValuesFunc(polID, containerRules.Executables.Allowed, bpf.AddValuesToPolicy); err != nil {
			return fmt.Errorf("failed to populate policy values for wp %s, container %s: %w", wpKey, containerName, err)
		}

		// Set policy mode
		mode := policymode.ParseMode(wp.Spec.Mode)
		if err := r.policyModeUpdateFunc(polID, mode, bpf.UpdateMode); err != nil {
			return fmt.Errorf("failed to set policy mode '%s' for wp %s, container %s: %w",
				mode.String(), wpKey, containerName, err)
		}

		// update the map with the policy ID
		r.wpState[wpKey][containerName] = polID
	}

	wpMap := r.wpState[wpKey]
	// Now we search for pods that match the policy
	for _, podState := range r.podCache {
		if !podState.matchPolicy(wp.Name) {
			continue
		}

		if err := r.applyPolicyToPod(podState, wpMap); err != nil {
			return err
		}
	}
	return nil
}

func (r *Resolver) updateWP(oldWp, newWp *v1alpha1.WorkloadPolicy) error {
	r.logger.Info(
		"update-wp-policy",
		"policy-name", newWp.Name,
		"policy-namespace", newWp.Namespace,
	)
	r.mu.Lock()
	defer r.mu.Unlock()

	wpKey := newWp.Namespace + "/" + newWp.Name
	state, exists := r.wpState[wpKey]
	if !exists {
		return fmt.Errorf("workload policy does not exist in internal state: %s", wpKey)
	}

	// For each update of the policy we re-enforce the executable list for each container even if it is the same
	for containerName, policyID := range state {
		oldRules := oldWp.Spec.RulesByContainer[containerName]
		newRules := newWp.Spec.RulesByContainer[containerName]

		// Skip if container doesn't exist in both (handle only existing containers)
		if oldRules == nil || newRules == nil {
			r.logger.Info(
				"non existing container, skipping",
				"container", containerName,
				"wp", wpKey,
			)
			continue
		}

		r.logger.Info(
			"setting executable list",
			"container", containerName,
			"wp", wpKey,
			"old-count", len(oldRules.Executables.Allowed),
			"new-count", len(newRules.Executables.Allowed),
		)

		// Atomically replace values in BPF maps
		if err := r.policyValuesFunc(policyID, newRules.Executables.Allowed, bpf.ReplaceValuesInPolicy); err != nil {
			return fmt.Errorf("failed to replace policy values for wp %s, container %s: %w",
				wpKey, containerName, err)
		}
	}

	r.logger.Info(
		"setting policy mode",
		"old-mode", oldWp.Spec.Mode,
		"new-mode", newWp.Spec.Mode,
		"wp", newWp.Name,
	)

	mode := policymode.ParseMode(newWp.Spec.Mode)

	for containerName, policyID := range state {
		if err := r.policyModeUpdateFunc(policyID, mode, bpf.UpdateMode); err != nil {
			return fmt.Errorf("failed to set policy mode '%s' for wp %s, container %s: %w",
				mode.String(), newWp.Name, containerName, err)
		}
	}

	return nil
}

func (r *Resolver) deleteWP(wp *v1alpha1.WorkloadPolicy) error {
	r.logger.Info(
		"delete-wp-policy",
		"policy-name", wp.Name,
		"policy-namespace", wp.Namespace,
	)
	r.mu.Lock()
	defer r.mu.Unlock()

	wpKey := wp.Namespace + "/" + wp.Name
	state, exists := r.wpState[wpKey]
	if !exists {
		return fmt.Errorf("workload policy does not exist in internal state: %s", wpKey)
	}
	delete(r.wpState, wpKey)

	for containerName, policyID := range state {
		// First we remove the association cgroupID -> PolicyID and then we will remove the policy values and modes

		// iteration + deletion on the ebpf map
		if err := r.cgroupToPolicyMapUpdateFunc(policyID, []CgroupID{}, bpf.RemovePolicy); err != nil {
			return fmt.Errorf("failed to remove policy from cgroup map: %w", err)
		}

		if err := r.policyValuesFunc(policyID, []string{}, bpf.RemoveValuesFromPolicy); err != nil {
			return fmt.Errorf("failed to remove policy values for wp %s, container %s: %w", wpKey, containerName, err)
		}

		if err := r.policyModeUpdateFunc(policyID, 0, bpf.DeleteMode); err != nil {
			return fmt.Errorf("failed to remove policy from policy mode map for wp %s, container %s: %w",
				wpKey, containerName, err)
		}
	}
	return nil
}

func resourceCheck(logger *slog.Logger, prefix string, obj interface{}) *v1alpha1.WorkloadPolicy {
	wp, ok := obj.(*v1alpha1.WorkloadPolicy)
	if !ok {
		logger.Error("unexpected object type", "method", prefix, "object", obj)
		return nil
	}
	return wp
}

func (r *Resolver) PolicyEventHandlers() cache.ResourceEventHandler {
	return cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			wp := resourceCheck(r.logger, "add-policy", obj)
			if wp == nil {
				return
			}
			if err := r.addWP(wp); err != nil {
				// todo!: we need to populate an internal status to report the failure to the user
				r.logger.Error("failed to add policy", "error", err)
				return
			}
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			newWp := resourceCheck(r.logger, "update-policy", newObj)
			if newWp == nil {
				return
			}
			oldWp := resourceCheck(r.logger, "update-policy", oldObj)
			if oldWp == nil {
				return
			}
			if err := r.updateWP(oldWp, newWp); err != nil {
				r.logger.Error("failed to update policy", "error", err)
				return
			}
		},
		DeleteFunc: func(obj interface{}) {
			wp := resourceCheck(r.logger, "delete-policy", obj)
			if wp == nil {
				return
			}
			if err := r.deleteWP(wp); err != nil {
				r.logger.Error("failed to delete policy", "error", err)
				return
			}
		},
	}
}
