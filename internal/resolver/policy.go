package resolver

import (
	"fmt"
	"log/slog"

	"github.com/neuvector/runtime-enforcer/api/v1alpha1"
	"github.com/neuvector/runtime-enforcer/internal/bpf"
	"github.com/neuvector/runtime-enforcer/internal/labels"
	"github.com/neuvector/runtime-enforcer/internal/types/policymode"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"
)

type PolicyID = uint64

const (
	// PolicyIDNone is used to indicate no policy associated with the cgroup.
	PolicyIDNone PolicyID = 0
)

type policy struct {
	id PolicyID

	// if namespace is "", policy applies to all namespaces
	namespace string

	containerSelector labels.Selector

	podSelector labels.Selector
}

func (pol *policy) getID() PolicyID {
	return pol.id
}

func (pol *policy) podInfoMatches(pod *podInfo) bool {
	return pol.podMatches(pod.namespace, pod.labels)
}

func (pol *policy) podMatches(podNs string, podLabels labels.Labels) bool {
	if pol.namespace != "" && podNs != pol.namespace {
		return false
	}
	var podLabels1 labels.Labels
	if podLabels != nil {
		podLabels1 = podLabels
	} else {
		podLabels1 = make(labels.Labels)
	}

	if _, ok := podLabels1[labels.K8sPodNamespace]; !ok {
		podLabels1[labels.K8sPodNamespace] = podNs
	}

	return pol.podSelector.Match(podLabels1)
}

func (pol *policy) containerMatchesFields(container *containerInfo) bool {
	containerFilterFields := labels.Labels{
		"name": container.name,
		"repo": container.repo,
	}
	return pol.containerSelector.Match(containerFilterFields)
}

func (pol *policy) getMatchingContainersCgroupIDs(containers map[ContainerID]*containerInfo) []CgroupID {
	var cgroupIDs []CgroupID
	for _, container := range containers {
		if pol.containerMatchesFields(container) {
			cgroupIDs = append(cgroupIDs, container.cgID)
		}
	}
	return cgroupIDs
}

func (r *Resolver) allocPolicyID() PolicyID {
	id := r.nextPolicyID
	r.nextPolicyID++
	return id
}

func (r *Resolver) addWP(wp *v1alpha1.WorkloadPolicy) error {
	r.logger.Info(
		"add-wp-policy",
		"policy-name", wp.Name,
		"policy-namespace", wp.Namespace,
	)
	wpKey := wp.Namespace + "/" + wp.Name
	if _, exists := r.wpState[wpKey]; exists {
		return fmt.Errorf("workload policy already exists in internal state: %s", wpKey)
	}

	r.wpState[wpKey] = make(map[string]PolicyID, len(wp.Spec.RulesByContainer))

	for containerName, containerRules := range wp.Spec.RulesByContainer {
		polID := r.allocPolicyID()
		r.logger.Info("create policy", "id", polID, "wp", wpKey)

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

		containerSelector := &metav1.LabelSelector{
			MatchExpressions: []metav1.LabelSelectorRequirement{
				{
					Key:      "name",
					Operator: metav1.LabelSelectorOpIn,
					Values:   []string{containerName},
				},
			},
		}
		podSelector := &metav1.LabelSelector{
			MatchLabels: map[string]string{
				v1alpha1.PolicyLabelKey: wp.Name,
			},
		}

		if err := r.AddPolicy(polID, wp.Namespace, podSelector, containerSelector); err != nil {
			return fmt.Errorf("failed to add policy to resolver for wp %s, container %s: %w", wpKey, containerName, err)
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

	wpKey := newWp.Namespace + "/" + newWp.Name
	state, exists := r.wpState[wpKey]
	if !exists {
		return fmt.Errorf("workload policy does not exist in internal state: %s", wpKey)
	}

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

	wpKey := wp.Namespace + "/" + wp.Name
	state, exists := r.wpState[wpKey]
	if !exists {
		return fmt.Errorf("workload policy does not exist in internal state: %s", wpKey)
	}
	delete(r.wpState, wpKey)

	for containerName, policyID := range state {
		if err := r.policyValuesFunc(policyID, []string{}, bpf.RemoveValuesFromPolicy); err != nil {
			return fmt.Errorf("failed to remove policy values for wp %s, container %s: %w", wpKey, containerName, err)
		}

		if err := r.policyModeUpdateFunc(policyID, 0, bpf.DeleteMode); err != nil {
			return fmt.Errorf("failed to remove policy from policy mode map for wp %s, container %s: %w",
				wpKey, containerName, err)
		}

		if err := r.DeletePolicy(policyID); err != nil {
			return fmt.Errorf("failed to remove policy from cgroup map for wp %s, container %s: %w",
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
