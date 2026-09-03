package debugger

import (
	"fmt"

	agentv1 "github.com/kubewarden/runtime-enforcer/proto/agent/v1"
)

type agentPodView struct {
	*agentv1.PodView
}

func newAgentPodViews(pods []*agentv1.PodView) []*agentPodView {
	wrapped := make([]*agentPodView, 0, len(pods))
	for _, pod := range pods {
		wrapped = append(wrapped, &agentPodView{PodView: pod})
	}
	return wrapped
}

func (v *agentPodView) sortKey() string {
	return v.Meta.GetId()
}

func (v *agentPodView) String() string {
	return fmt.Sprintf("%s/%s (%s)", v.Meta.GetNamespace(), v.Meta.GetName(), v.Meta.GetId())
}

func (v *agentPodView) getNamespace() string {
	return v.Meta.GetNamespace()
}

func (v *agentPodView) getName() string {
	return v.Meta.GetName()
}

func (v *agentPodView) getContainers() map[containerID]*agentv1.ContainerMeta {
	return v.GetContainers()
}
