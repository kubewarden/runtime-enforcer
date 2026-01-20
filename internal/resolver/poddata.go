package resolver

import "github.com/neuvector/runtime-enforcer/api/v1alpha1"

type ContainerData struct {
	Name     string
	CgroupID CgroupID
}

// PodData is the format for pod metadata that resolver consumers should provide.
type PodData struct {
	UID              PodID
	Name             string
	Namespace        string
	WorkloadName     string
	WorkloadType     string
	PolicyLabelValue string
	ContainersData   map[string]*ContainerData
}

// convert external notation into internal state used in the cache.
func podDataToState(pod *PodData) *podState {
	state := &podState{
		info: &podInfo{
			name:         pod.Name,
			namespace:    pod.Namespace,
			podID:        pod.UID,
			workloadName: pod.WorkloadName,
			workloadType: pod.WorkloadType,
			// todo!: remove it
			labels: map[string]string{
				v1alpha1.PolicyLabelKey: pod.PolicyLabelValue,
			},
		},
	}
	for cID, cinfo := range pod.ContainersData {
		state.containers[cID] = &containerInfo{
			name: cinfo.Name,
			cgID: cinfo.CgroupID,
		}
	}
	return state
}
