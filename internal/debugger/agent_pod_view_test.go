package debugger

import (
	"testing"

	agentv1 "github.com/kubewarden/runtime-enforcer/proto/agent/v1"
	"github.com/stretchr/testify/require"
)

func TestAgentPodViewHelpers(t *testing.T) {
	podUID := "uid-1"
	podName := "pod-a"
	podNamespace := "default"
	containerID1 := "cid1"
	containerName1 := "c1"

	agentView := &agentPodView{
		PodView: &agentv1.PodView{
			Meta: &agentv1.PodMeta{
				Id:        podUID,
				Name:      podName,
				Namespace: podNamespace,
			},
			Containers: map[string]*agentv1.ContainerMeta{
				containerID1: {Id: containerID1, Name: containerName1},
			},
		},
	}

	require.Equal(t, podUID, agentView.sortKey())
	require.Equal(t, podName, agentView.getName())
	require.Equal(t, podNamespace, agentView.getNamespace())
	require.Len(t, agentView.getContainers(), 1)
	require.Equal(t, containerID1, agentView.getContainers()[containerID1].GetId())
	require.Equal(t, containerName1, agentView.getContainers()[containerID1].GetName())
}
