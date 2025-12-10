package resolver

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

func (pod *podState) getCgroupIDsHash() map[CgroupID]bool {
	cgroupIDs := make(map[CgroupID]bool)
	for _, container := range pod.containers {
		cgroupIDs[container.cgID] = true
	}
	return cgroupIDs
}

func (pod *podState) getInfo() *podInfo {
	return pod.info
}

func (pod *podState) getContainers() map[ContainerID]*containerInfo {
	return pod.containers
}
