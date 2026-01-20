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
