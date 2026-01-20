package resolver

import "github.com/neuvector/runtime-enforcer/api/v1alpha1"

type podState struct {
	info       *podInfo
	containers map[ContainerID]*containerInfo
}

func (pod *podState) getCgroupIDs() []CgroupID {
	var cgroupIDs []CgroupID
	for _, container := range pod.containers {
		cgroupIDs = append(cgroupIDs, container.cgID)
	}
	return cgroupIDs
}

//nolint:unused // next step
func (pod *podState) getCgroupIDsHash() map[CgroupID]bool {
	cgroupIDs := make(map[CgroupID]bool)
	for _, container := range pod.containers {
		cgroupIDs[container.cgID] = true
	}
	return cgroupIDs
}

//nolint:unused // next step
func (pod *podState) getInfo() *podInfo {
	return pod.info
}

//nolint:unused // next step
func (pod *podState) getContainers() map[ContainerID]*containerInfo {
	return pod.containers
}

func (pod *podState) matchPolicy(policyName string) bool {
	v, ok := pod.info.labels[v1alpha1.PolicyLabelKey]
	if !ok || v != policyName {
		return false
	}
	return true
}

func (pod *podState) policyLabel() string {
	return pod.info.labels[v1alpha1.PolicyLabelKey]
}

func (pod *podState) podName() string {
	return pod.info.name
}

func (pod *podState) podNamespace() string {
	return pod.info.namespace
}
