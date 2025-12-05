package resolver

import (
	"context"
	"fmt"
	"log/slog"
	"sync"

	"github.com/neuvector/runtime-enforcer/internal/bpf"
	"github.com/neuvector/runtime-enforcer/internal/labels"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"
	cmCache "sigs.k8s.io/controller-runtime/pkg/cache"
)

type CgroupID = uint64
type ContainerID = string
type PodID = string
type ContainerName = string
type operation int

type Resolver struct {
	// let's see if we can split this unique lock in multiple locks later
	mu     sync.Mutex
	logger *slog.Logger
	// todo!: we should add a cache with deleted pods/containers so that we can resolve also recently deleted ones
	podCache                    map[PodID]*podState
	cgroupIDToPodID             map[CgroupID]PodID
	policies                    []policy
	cgTrackerUpdateFunc         func(cgID uint64, cgroupPath string) error
	cgroupToPolicyMapUpdateFunc func(polID PolicyID, cgroupIDs []CgroupID, op bpf.CgroupPolicyOperation) error
	criResolver                 *criResolver
}

func NewResolver(ctx context.Context, logger *slog.Logger, informer cmCache.Informer,
	cgTrackerUpdateFunc func(cgID uint64, cgroupPath string) error,
	cgroupToPolicyMapUpdateFunc func(polID PolicyID, cgroupIDs []CgroupID, op bpf.CgroupPolicyOperation) error) (*Resolver, error) {
	var err error
	r := &Resolver{
		logger:                      logger.With("component", "resolver"),
		podCache:                    make(map[PodID]*podState),
		cgroupIDToPodID:             make(map[CgroupID]PodID),
		cgTrackerUpdateFunc:         cgTrackerUpdateFunc,
		cgroupToPolicyMapUpdateFunc: cgroupToPolicyMapUpdateFunc,
	}

	r.criResolver, err = newCRIResolver(ctx, r.logger)
	if err != nil {
		return nil, err
	}

	informer.AddEventHandler(r.EventHandlers())
	// todo!: add handlers for the rthook
	// todo!: we can do a first scan of all existing containers to populate the cache initially
	return r, nil
}

/////////////////////
// Pod handlers
/////////////////////

func (r *Resolver) recomputePodPolicies(state *podState) {
	// Cgroups that are involved in new policies
	involvedCgroupIDs := make(map[CgroupID]bool)
	for _, pol := range r.policies {
		if !pol.podInfoMatches(state.getInfo()) {
			continue
		}
		cgroupIDs := pol.getMatchingContainersCgroupIDs(state.getContainers())
		if len(cgroupIDs) == 0 {
			continue
		}
		for _, cgID := range cgroupIDs {
			involvedCgroupIDs[cgID] = true
		}
		if err := r.cgroupToPolicyMapUpdateFunc(pol.id, cgroupIDs, bpf.AddPolicyToCgroups); err != nil {
			// for now we log but this is not enough since the policy won't be applied
			r.logger.Error("failed to associate cgroups with policy after label change",
				"cgroup-ids", cgroupIDs,
				"policy-id", pol.id,
				"error", err,
			)
		}
	}

	// We should delete cgroup IDs that are not involved in any policy anymore, since they could still be bounded to old policies associated to old labels.
	for cgID, _ := range state.getCgroupIDsHash() {
		if !involvedCgroupIDs[cgID] {
			if err := r.cgroupToPolicyMapUpdateFunc(PolicyIDNone, []CgroupID{cgID}, bpf.RemoveCgroups); err != nil {
				r.logger.Error("failed to remove no more involved cgroup from policy map",
					"cgroup-id", cgID,
					"error", err,
				)
			}
		}
	}
}

func (r *Resolver) applyPoliciesToPod(state *podState) {
	for _, pol := range r.policies {
		if !pol.podInfoMatches(state.getInfo()) {
			continue
		}
		cgroupIDs := pol.getMatchingContainersCgroupIDs(state.getContainers())
		if len(cgroupIDs) == 0 {
			continue
		}
		if err := r.cgroupToPolicyMapUpdateFunc(pol.id, cgroupIDs, bpf.AddPolicyToCgroups); err != nil {
			// for now we log but this is not enough since the policy won't be applied
			r.logger.Error("failed to associate cgroups with policy",
				"cgroup-ids", cgroupIDs,
				"policy-id", pol.id,
				"error", err,
			)
		}
	}
}

func (r *Resolver) podContainersResolveCgroups(state *podState) {
	for cID, cInfo := range state.containers {
		if cInfo.cgID != 0 {
			// we assume it is already resolved in a previous step
			continue
		}

		// We do the resolution in a synchronous way
		// todo!: we could use the file system to resolve the cgroup if we see it is more efficient
		cgID, cgPath, err := r.criResolver.resolveCgroup(cID)
		if err != nil {
			// todo!: we should retry later?
			r.logger.Error("failed to resolve cgroup ID", "containerID", cID, "error", err)
			continue
		}
		r.cgroupIDToPodID[cgID] = state.info.podID
		cInfo.cgID = cgID
		if err := r.cgTrackerUpdateFunc(cgID, cgPath); err != nil {
			r.logger.Error("failed to update cgroup tracker", "cgroupID", cgID, "cgroupPath", cgPath, "error", err)
		}
	}
}

func (r *Resolver) addPod(pod *corev1.Pod) {
	r.mu.Lock()
	defer r.mu.Unlock()

	// We are in a create we should not have the pod already in the cache
	state, ok := r.podCache[PodID(pod.UID)]
	if ok {
		r.logger.Error("add-pod: pod already exists in podCache", "old pod info", state.info, "pod-name", pod.Name, "pod-namespace", pod.Namespace, "pod-uid", string(pod.UID))
		return
	}

	state = &podState{
		info: getPodInfo(pod),
		// populate containers info, but we still miss the cgroup for each container since we receive the pod from k8s api server
		containers: podContainersInfoWithoutCgroups(pod),
	}
	r.podCache[PodID(pod.UID)] = state

	r.podContainersResolveCgroups(state)

	// Now ideally we should have all cgroup IDs resolved, so we can populate the policy map
	r.applyPoliciesToPod(state)
}

func (r *Resolver) deletePod(pod *corev1.Pod) {
	r.mu.Lock()
	defer r.mu.Unlock()

	// We are in a create we should not have the pod already in the cache
	state, ok := r.podCache[PodID(pod.UID)]
	if !ok {
		r.logger.Error("delete-pod: pod does not exist in podCache", "pod-name", pod.Name, "pod-namespace", pod.Namespace, "pod-uid", string(pod.UID))
		return
	}

	delete(r.podCache, PodID(pod.UID))

	cgroupIDs := state.getCgroupIDs()
	if len(cgroupIDs) == 0 {
		r.logger.Warn("delete-pod: pod has no cgroups associated", "pod-name", pod.Name, "pod-namespace", pod.Namespace, "pod-uid", string(pod.UID))
		return
	}

	for _, cgID := range cgroupIDs {
		delete(r.cgroupIDToPodID, cgID)
	}

	if err := r.cgroupToPolicyMapUpdateFunc(PolicyIDNone, cgroupIDs, bpf.RemoveCgroups); err != nil {
		// for now we log but this is not enough since the policy won't be applied
		r.logger.Error("failed to update policy map",
			"error", err,
			"pod-id", PodID(pod.UID),
		)
	}
}

func (r *Resolver) updatePodContainers(state *podState, newContainers map[ContainerID]*containerInfo) {
	// We handle deleted containers first
	for cid, info := range state.containers {
		if _, exists := newContainers[cid]; exists {
			// the container is still present
			continue
		}
		r.logger.Debug("remove container from pod", "pod", state.info.name, "container", info.name)
		// We delete the container from the pod
		delete(state.containers, cid)
		// We remove the cgroup from the global cache
		delete(r.cgroupIDToPodID, info.cgID)
		// We remove the cgroup from the policy map
		if err := r.cgroupToPolicyMapUpdateFunc(PolicyIDNone, []CgroupID{info.cgID}, bpf.RemoveCgroups); err != nil {
			r.logger.Error("failed to update policy map", "error", err, "cgroupID", info.cgID)
		}
	}

	// Now we add new containers
	addedNewContainer := false
	for cid, info := range newContainers {
		if _, exists := state.containers[cid]; exists {
			// the container is still present
			continue
		}
		addedNewContainer = true
		// We add the container to the pod
		state.containers[cid] = info
	}

	if addedNewContainer {
		// We resolve cgroups for new containers
		r.podContainersResolveCgroups(state)
		// We apply policies to the pod again to consider new containers
		r.applyPoliciesToPod(state)
	}
}

func (r *Resolver) updatePod(oldPod, newPod *corev1.Pod) {
	r.mu.Lock()
	defer r.mu.Unlock()

	// We are in a create we should not have the pod already in the cache
	state, ok := r.podCache[PodID(newPod.UID)]
	if !ok {
		r.logger.Error("update-pod: pod does not exist in podCache", "pod-name", newPod.Name, "pod-namespace", newPod.Namespace, "pod-uid", newPod.UID)
		return
	}

	// Sanity check: make sure the oldPod matches the state we have
	if state.info.labels.Cmp(oldPod.Labels) {
		r.logger.Error("update-pod: old pod labels are different from the ones in the state", "old pod labels", oldPod.Labels, "state labels", state.info.labels)
		return
	}

	//////////////////////////
	// Label change (I'm not sure we should tolerate this case at all)
	//////////////////////////

	if state.info.labels.Cmp(newPod.Labels) {
		r.logger.Debug("pod labels changed, recomputing policies", "old labels", state.info.labels, "new labels", newPod.Labels)
		state.info.labels = newPod.Labels
		r.recomputePodPolicies(state)
		// we should return here since there should be no other changes
		return
	}

	//////////////////////////
	// Container changes (This is possible for example in case of backoff restarts)
	//////////////////////////

	r.updatePodContainers(state, podContainersInfoWithoutCgroups(newPod))
}

// todo!: Using an informer is ok for now, but it is difficult to manage critical failures, for now we log errors but we should really handle them. One solution could be to use a gRPC channel instead of informers. An external controller will send to each agent pod/workload-policies updates only when necessary and will handle retry or policy redeployment in case of failure.
func (r *Resolver) EventHandlers() cache.ResourceEventHandler {
	return cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			pod, ok := obj.(*corev1.Pod)
			if !ok {
				r.logger.Error("add-pod handler: unexpected object type", "object", obj)
				return
			}
			r.logger.Debug("add-pod handler called", "pod-name", pod.Name, "pod-namespace", pod.Namespace, "pod-uid", string(pod.UID))
			r.addPod(pod)
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			oldPod, ok := oldObj.(*corev1.Pod)
			if !ok {
				r.logger.Error("update-pod handler: unexpected object type", "old object", oldObj)
				return
			}
			newPod, ok := newObj.(*corev1.Pod)
			if !ok {
				r.logger.Error("update-pod handler: unexpected object type", "new object", newObj)
				return
			}
			r.logger.Debug("update-pod handler called", "pod-name", newPod.Name, "pod-namespace", newPod.Namespace, "pod-uid", string(newPod.UID))
			r.updatePod(oldPod, newPod)
		},
		DeleteFunc: func(obj interface{}) {
			// Remove all containers for this pod
			pod, ok := obj.(*corev1.Pod)
			if !ok {
				r.logger.Error("delete-pod handler: unexpected object type", "object", obj)
				return
			}
			r.logger.Debug("delete-pod handler called", "pod-name", pod.Name, "pod-namespace", pod.Namespace, "pod-uid", string(pod.UID))
			r.deletePod(pod)
		},
	}
}

/////////////////////
// Policy handlers
/////////////////////

func (r *Resolver) findPolicy(id PolicyID) *policy {
	for i := range r.policies {
		if r.policies[i].id == id {
			return &r.policies[i]
		}
	}
	return nil
}

func (r *Resolver) deletePolicy(id PolicyID) *policy {
	for i, pol := range r.policies {
		if pol.getID() == id {
			r.policies = append(r.policies[:i], r.policies[i+1:]...)
			return &pol
		}
	}
	return nil
}

func (r *Resolver) AddPolicy(polID PolicyID, namespace string, podLabelSelector *metav1.LabelSelector,
	containerLabelSelector *metav1.LabelSelector) error {
	r.logger.Info("start adding policy", "policy_id", polID)

	podSelector, err := labels.SelectorFromLabelSelector(podLabelSelector)
	if err != nil {
		return err
	}

	containerSelector, err := labels.SelectorFromLabelSelector(containerLabelSelector)
	if err != nil {
		return err
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	pol := r.findPolicy(polID)
	if pol != nil {
		panic(fmt.Sprintf("policy with id %d already exists", polID))
	}

	newPol := policy{
		id:                polID,
		namespace:         namespace,
		podSelector:       podSelector,
		containerSelector: containerSelector,
	}

	// Need to find all cgroup IDs that match this policy now
	cgroupIDs := make([]CgroupID, 0)
	for _, podState := range r.podCache {
		if !newPol.podInfoMatches(podState.getInfo()) {
			continue
		}
		matchingCgroups := newPol.getMatchingContainersCgroupIDs(podState.getContainers())
		r.logger.Debug("found matching cgroups", "pod-name", podState.info.name, "policy_id", polID, "cgroup_ids", matchingCgroups)
		cgroupIDs = append(cgroupIDs, matchingCgroups...)
	}

	if err := r.cgroupToPolicyMapUpdateFunc(polID, cgroupIDs, bpf.AddPolicyToCgroups); err != nil {
		return fmt.Errorf("updating policy map with cgroups failed: %w", err)
	}

	r.policies = append(r.policies, newPol)
	r.logger.Info("finished adding policy", "policy_id", polID)
	return nil
}

func (r *Resolver) DeletePolicy(polID PolicyID) error {
	r.logger.Info("start deleting policy", "policy_id", polID)

	r.mu.Lock()
	defer r.mu.Unlock()

	pol := r.deletePolicy(polID)
	if pol == nil {
		panic(fmt.Sprintf("policy with id %d does not exist", polID))
	}

	// iteration + deletion on the ebpf map
	if err := r.cgroupToPolicyMapUpdateFunc(polID, []CgroupID{}, bpf.RemovePolicy); err != nil {
		return fmt.Errorf("updating policy map with cgroups failed: %w", err)
	}

	r.logger.Info("finished deleting policy", "policy_id", polID)
	return nil
}
