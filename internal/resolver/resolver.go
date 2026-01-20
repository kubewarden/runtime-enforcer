package resolver

import (
	"context"
	"fmt"
	"log/slog"
	"path/filepath"
	"sync"

	"github.com/containerd/nri/pkg/api"
	"github.com/neuvector/runtime-enforcer/api/v1alpha1"
	"github.com/neuvector/runtime-enforcer/internal/bpf"
	"github.com/neuvector/runtime-enforcer/internal/cgroups"
	"github.com/neuvector/runtime-enforcer/internal/types/policymode"
	corev1 "k8s.io/api/core/v1"
)

type CgroupID = uint64
type ContainerID = string
type PodID = string
type ContainerName = string

type Resolver struct {
	// let's see if we can split this unique lock in multiple locks later
	mu     sync.Mutex
	logger *slog.Logger
	// todo!: we should add a cache with deleted pods/containers so that we can resolve also recently deleted ones
	podCache        map[PodID]*podState
	cgroupIDToPodID map[CgroupID]PodID
	criResolver     *criResolver

	nextPolicyID                PolicyID
	wpState                     map[string]map[string]PolicyID
	policyValuesFunc            func(policyID PolicyID, values []string, op bpf.PolicyValuesOperation) error
	policyModeUpdateFunc        func(policyID PolicyID, mode policymode.Mode, op bpf.PolicyModeOperation) error
	cgTrackerUpdateFunc         func(cgID uint64, cgroupPath string) error
	cgroupToPolicyMapUpdateFunc func(polID PolicyID, cgroupIDs []CgroupID, op bpf.CgroupPolicyOperation) error
	nriSocketPath               string
	nriPluginIndex              string
}

func NewResolver(
	ctx context.Context,
	logger *slog.Logger,
	cgTrackerUpdateFunc func(cgID uint64, cgroupPath string) error,
	cgroupToPolicyMapUpdateFunc func(polID PolicyID, cgroupIDs []CgroupID, op bpf.CgroupPolicyOperation) error,
	policyValuesFunc func(policyID uint64, values []string, op bpf.PolicyValuesOperation) error,
	policyModeUpdateFunc func(policyID uint64, mode policymode.Mode, op bpf.PolicyModeOperation) error,
	nriSocketPath string,
	nriPluginIndex string,
) (*Resolver, error) {
	var err error
	r := &Resolver{
		logger:                      logger.With("component", "resolver"),
		podCache:                    make(map[PodID]*podState),
		cgroupIDToPodID:             make(map[CgroupID]PodID),
		cgTrackerUpdateFunc:         cgTrackerUpdateFunc,
		cgroupToPolicyMapUpdateFunc: cgroupToPolicyMapUpdateFunc,
		policyValuesFunc:            policyValuesFunc,
		policyModeUpdateFunc:        policyModeUpdateFunc,
		wpState:                     make(map[string]map[string]PolicyID),
		nextPolicyID:                PolicyID(1),
		nriSocketPath:               nriSocketPath,
		nriPluginIndex:              nriPluginIndex,
	}

	r.criResolver, err = newCRIResolver(ctx, r.logger)
	if err != nil {
		return nil, err
	}

	err = r.StartNriPluginWithRetry(ctx, r.StartNriPlugin)
	if err != nil {
		return nil, fmt.Errorf("failed to start nri plugin: %w", err)
	}

	// todo!: we can do a first scan of all existing containers to populate the cache initially
	return r, nil
}

/////////////////////
// Pod handlers
/////////////////////

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
		if err = r.cgTrackerUpdateFunc(cgID, cgPath); err != nil {
			r.logger.Error("failed to update cgroup tracker", "cgroupID", cgID, "cgroupPath", cgPath, "error", err)
		}
	}
}

func (r *Resolver) AddPod(pod *corev1.Pod) {
	r.mu.Lock()
	defer r.mu.Unlock()

	// We are in a create we should not have the pod already in the cache
	state, ok := r.podCache[PodID(pod.UID)]
	if ok {
		r.logger.Error(
			"add-pod: pod already exists in podCache",
			"old pod info", state.info,
			"pod-name", pod.Name,
			"pod-namespace", pod.Namespace,
			"pod-uid", string(pod.UID),
		)
		return
	}

	state = &podState{
		// When a pod is created it should have all the labels necessary for the workload resolution (e.g. pod-template-hash). If we face some issues we can consider to update the workload type/name also with pod updates.
		info: getPodInfo(pod),
		// populate containers info, but we still miss the cgroup for each container since we receive the pod from k8s api server
		containers: podContainersInfoWithoutCgroups(pod),
	}
	r.podCache[PodID(pod.UID)] = state

	r.podContainersResolveCgroups(state)

	// Now ideally we should have all cgroup IDs resolved, so we can populate the policy map
	if err := r.applyPolicyToPodIfPresent(state); err != nil {
		r.logger.Error("failed to apply policy to pod",
			"error", err,
		)
	}
}

func (r *Resolver) DeletePod(pod *corev1.Pod) {
	r.mu.Lock()
	defer r.mu.Unlock()

	state, ok := r.podCache[PodID(pod.UID)]
	if !ok {
		r.logger.Error(
			"delete-pod: pod does not exist in podCache",
			"pod-name",
			pod.Name,
			"pod-namespace",
			pod.Namespace,
			"pod-uid",
			string(pod.UID),
		)
		return
	}

	delete(r.podCache, PodID(pod.UID))

	cgroupIDs := state.getCgroupIDs()
	if len(cgroupIDs) == 0 {
		r.logger.Warn(
			"delete-pod: pod has no cgroups associated",
			"pod-name",
			pod.Name,
			"pod-namespace",
			pod.Namespace,
			"pod-uid",
			string(pod.UID),
		)
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
		if err := r.applyPolicyToPodIfPresent(state); err != nil {
			r.logger.Error("failed to apply policy to pod",
				"error", err,
			)
		}
	}
}

func (r *Resolver) UpdatePod(_ *corev1.Pod, newPod *corev1.Pod) {
	r.mu.Lock()
	defer r.mu.Unlock()

	state, ok := r.podCache[PodID(newPod.UID)]
	if !ok {
		r.logger.Error("update-pod: pod does not exist in podCache",
			"pod-name",
			newPod.Name,
			"pod-namespace",
			newPod.Namespace,
			"pod-uid",
			newPod.UID)
		return
	}

	//////////////////////////
	// Container changes
	//////////////////////////

	r.updatePodContainers(state, podContainersInfoWithoutCgroups(newPod))
}

/////////////////////
// Policy handlers
/////////////////////

func (r *Resolver) checkPolicyFromNRI(
	ctx context.Context,
	pod *api.PodSandbox,
	container *api.Container,
	cgID uint64,
) error {
	var err error

	// todo!: in next iteration we should reuse method `applyPolicyToPodIfPresent`
	policyName := pod.GetLabels()[v1alpha1.PolicyLabelKey]
	if policyName == "" {
		// pod has no policy
		return nil
	}
	key := fmt.Sprintf("%s/%s", pod.GetNamespace(), policyName)

	pol, ok := r.wpState[key]
	if !ok {
		// policy not found
		return fmt.Errorf("pod '%s/%s' has policy '%s' but the policy does not exist",
			pod.GetNamespace(),
			pod.GetName(),
			policyName,
		)
	}

	polID, ok := pol[container.GetName()]
	if !ok {
		return fmt.Errorf("policy '%s' has no container '%s' but pod '%s/%s' has it",
			policyName,
			container.GetName(),
			pod.GetNamespace(),
			pod.GetName(),
		)
	}

	r.logger.InfoContext(
		ctx,
		"assigning policy via NRI",
		"namespace",
		pod.GetNamespace(),
		"podName",
		pod.GetName(),
		"containerName",
		container.GetName(),
		"cgID",
		cgID,
		"policyID",
		polID,
	)

	if err = r.cgroupToPolicyMapUpdateFunc(polID, []CgroupID{cgID}, bpf.AddPolicyToCgroups); err != nil {
		r.logger.ErrorContext(ctx, "failed to update the cgroup path and policy id in cgPath ebpf map", "error", err)
		return err
	}
	return nil
}

func (r *Resolver) updateCgroupTrackerFromNRI(
	ctx context.Context,
	cgID uint64,
	cgPath string,
	podID string,
) error {
	var err error

	r.cgroupIDToPodID[cgID] = podID
	if err = r.cgTrackerUpdateFunc(cgID, cgPath); err != nil {
		return fmt.Errorf("failed to update cgroup tracker: %w", err)
	}

	r.logger.InfoContext(
		ctx,
		"updating cgroup tracker",
		"cgID",
		cgID,
		"cgPath",
		cgPath,
		"podID",
		podID,
	)
	return nil
}

func (r *Resolver) AddPodFromNRI(
	ctx context.Context,
	pod *api.PodSandbox,
	container *api.Container,
) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	// 1. retrieve cgroup ID
	cgroupPath, err := ParseCgroupsPath(container.GetLinux().GetCgroupsPath())
	if err != nil {
		return fmt.Errorf("failed to parse cgroup path: %w", err)
	}

	cgRoot, err := cgroups.GetHostCgroupRoot()
	if err != nil {
		return fmt.Errorf("failed to get host cgroup root: %w", err)
	}

	cgPath := filepath.Join(cgRoot, cgroupPath)

	cgID, err := cgroups.GetCgroupIDFromPath(cgPath)
	if err != nil {
		return fmt.Errorf("failed to get cgroup ID from path %s: %w", cgPath, err)
	}

	// 2. Update cgroup tracker, so we can track execve events
	err = r.updateCgroupTrackerFromNRI(ctx, cgID, cgPath, pod.GetUid())
	if err != nil {
		return fmt.Errorf("failed to update cgroup tracker: %w", err)
	}

	// 3. check if a policy should be applied.
	err = r.checkPolicyFromNRI(ctx, pod, container, cgID)
	if err != nil {
		return fmt.Errorf("failed to update policy: %w", err)
	}
	return nil
}
