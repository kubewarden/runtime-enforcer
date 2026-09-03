package resolver

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/kubewarden/runtime-enforcer/internal/bpf"
)

const nriSyncInProgressMsg = "waiting for NRI synchronization to complete"

func convertPodData(pod PodInput) *podEntry {
	return &podEntry{
		meta:       &pod.Meta,
		containers: make(map[ContainerID]*ContainerMeta),
	}
}

func (r *Resolver) AddPodContainerFromNri(pod PodInput) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	// NRI provides just one container of a pod, so it's possible we already have some containers for this pod.
	podID := pod.Meta.ID
	state, ok := r.podCache[podID]
	if !ok {
		// we need to add the pod to the cache from 0
		state = convertPodData(pod)
	}

	for containerID, container := range pod.Containers {
		if info, exists := state.containers[containerID]; exists {
			// this is possible for example when there is a restart in the NRI plugin and we receive all the data again.
			// cID and containerName should never change but as an extra check we return an error for now.
			if info.CgroupID == container.CgroupID && info.Name == container.Name {
				// If everything is identical, as expected, we can just continue
				continue
			}
			// If it's different, this is unexpected and we return an error to avoid potential issues
			// with wrong cgroupID -> pod association in the cache.
			return fmt.Errorf("containerID %s for pod %s already exists. old (name: %s,cID: %d) new (name: %s,cID: %d)",
				containerID,
				pod.Meta.Name,
				info.Name,
				info.CgroupID,
				container.Name,
				container.CgroupID)
		}

		state.containers[containerID] = &container.ContainerMeta

		// populate the cgroup cache
		r.cgroupIDToPodID[container.CgroupID] = podID

		// update the cgtracker map
		if err := r.cgTrackerUpdateFunc(container.CgroupID, container.CgroupPath); err != nil {
			return fmt.Errorf(
				"failed to update cgroup tracker map for pod %s, container %s: %w",
				pod.Meta.Name,
				container.Name,
				err,
			)
		}
	}

	// we update back the cache
	r.podCache[podID] = state

	if err := r.applyPolicyToPodIfPresent(state); err != nil {
		return fmt.Errorf("failed to apply policy to pod: %w", err)
	}
	return nil
}

func (r *Resolver) RemovePodContainerFromNri(podID PodID, containerID ContainerID) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	state, ok := r.podCache[podID]
	if !ok {
		// This can happen with containerd when its NRI implementation doesn't send the containers with EXITED state in Synchronize() call,
		// and we still see the exited container in RemoveContainer() call.
		// Given the pod is not present in the cache, there is nothing we can do here.
		r.logger.Info("the pod being removed is not in the cache. It was probably not in an active state.",
			"containerID", containerID,
			"podID", podID)
		return nil
	}

	// remove the container from the pod
	container, ok := state.containers[containerID]
	if !ok {
		// This can happen if during synchronize the container was in a not ready state and it was not sent,
		// but then we receive the remove event for that container.
		r.logger.Info("container not found", "containerID", containerID, "podID", podID)
		return nil
	}

	if len(state.containers) == 1 {
		// if this was the last container, we need to remove the pod from the cache
		delete(r.podCache, podID)
	} else {
		// otherwise we just delete the container inside the pod
		delete(state.containers, containerID)
	}

	// remove the cgroup ID from the cache
	delete(r.cgroupIDToPodID, container.CgroupID)

	return r.cgroupToPolicyMapUpdateFunc(PolicyIDNone, []CgroupID{container.CgroupID}, bpf.RemoveCgroups)
}

func (r *Resolver) NRISynchronized() {
	r.nriSynchronized.Store(true)
}

func (r *Resolver) IsNRISynchronized() bool {
	return r.nriSynchronized.Load()
}

func (r *Resolver) Ping(req *http.Request) error {
	if !r.nriSynchronized.Load() {
		r.logger.InfoContext(req.Context(), nriSyncInProgressMsg)
		return errors.New(nriSyncInProgressMsg)
	}
	return nil
}
