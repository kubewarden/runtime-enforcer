package resolver

import (
	"errors"
	"fmt"

	"github.com/neuvector/runtime-enforcer/internal/labels"
)

type podInfo struct {
	// this should become a separate type if needed
	podID        string
	namespace    string
	name         string
	workloadName string
	workloadType string
	labels       labels.Labels
}

type KubeInfo struct {
	PodID         string
	PodName       string
	Namespace     string
	ContainerName string
	WorkloadName  string
	WorkloadType  string
	ContainerID   string
	Labels        labels.Labels
}

var (
	// ErrMissingPodUID is returned when no Pod UID could be found for the given cgroup ID.
	ErrMissingPodUID = errors.New("missing pod UID for cgroup ID")

	// ErrMissingPodInfo is returned when the Pod UID was found, but
	// the detailed Pod information is missing.
	ErrMissingPodInfo = errors.New("missing pod info for found pod ID")
)

func (r *Resolver) GetKubeInfo(cgID CgroupID) (*KubeInfo, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	podID, ok := r.cgroupIDToPodID[cgID]
	if !ok {
		return nil, fmt.Errorf("%w: %d", ErrMissingPodUID, cgID)
	}

	pod, ok := r.podCache[podID]
	if !ok {
		return nil, fmt.Errorf("%w: %s (cgroup ID %d)", ErrMissingPodInfo, podID, cgID)
	}

	containerName := notFound
	containerID := notFound
	for cID, info := range pod.containers {
		if cgID == info.cgID {
			containerName = info.name
			containerID = cID
			break
		}
	}

	return &KubeInfo{
		PodID:         podID,
		PodName:       pod.info.name,
		Namespace:     pod.info.namespace,
		ContainerName: containerName,
		WorkloadName:  pod.info.workloadName,
		WorkloadType:  pod.info.workloadType,
		ContainerID:   containerID,
		Labels:        pod.info.labels,
	}, nil
}
