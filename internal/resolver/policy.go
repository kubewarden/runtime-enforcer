package resolver

import (
	"github.com/neuvector/runtime-enforcer/internal/labels"
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
