package resolver

import (
	"maps"

	"github.com/kubewarden/runtime-enforcer/api/v1alpha1"
)

// podEntry is the internal representation of a pod inside our cache.
type podEntry struct {
	meta       *PodMeta
	containers map[ContainerID]*ContainerMeta
}

func (pod *podEntry) matchPolicy(policyName, policyNamespace string) bool {
	// now we need to check if the pod is in the same namespace of the policy since our policies are namespaced.
	return pod.policyName() == policyName && pod.podNamespace() == policyNamespace
}

func (pod *podEntry) policyName() string {
	return pod.meta.Labels[v1alpha1.PolicyLabelKey]
}

func (pod *podEntry) podName() string {
	return pod.meta.Name
}

func (pod *podEntry) podNamespace() string {
	return pod.meta.Namespace
}

func (pod *podEntry) toView() PodView {
	view := PodView{
		Meta:       *pod.meta,
		Containers: make(map[ContainerID]ContainerMeta),
	}
	// We need a deep copy
	view.Meta.Labels = make(map[string]string, len(pod.meta.Labels))
	maps.Copy(view.Meta.Labels, pod.meta.Labels)
	for id, meta := range pod.containers {
		view.Containers[id] = *meta
	}
	return view
}
