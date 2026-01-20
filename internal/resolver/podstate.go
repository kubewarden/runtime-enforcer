package resolver

type PodState struct {
	info       *podInfo
	containers map[ContainerID]*containerInfo
}

func (pod *PodState) podUid() PodID {
	return pod.info.podID
}

func (pod *PodState) podName() PodID {
	return pod.info.name
}

func (pod *PodState) podNameSpace() PodID {
	return pod.info.namespace
}

func (pod *PodState) getCgroupIDs() []CgroupID {
	var cgroupIDs []CgroupID
	for _, container := range pod.containers {
		cgroupIDs = append(cgroupIDs, container.cgID)
	}
	return cgroupIDs
}

func (pod *PodState) getCgroupIDsHash() map[CgroupID]bool {
	cgroupIDs := make(map[CgroupID]bool)
	for _, container := range pod.containers {
		cgroupIDs[container.cgID] = true
	}
	return cgroupIDs
}

func (pod *PodState) getInfo() *podInfo {
	return pod.info
}

func (pod *PodState) getContainers() map[ContainerID]*containerInfo {
	return pod.containers
}
