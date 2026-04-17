package main

import (
	"bytes"
	"fmt"
	"testing"

	agentv1 "github.com/rancher-sandbox/runtime-enforcer/proto/agent/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

func TestContainerIDFromContainerStatus(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "containerd prefix is stripped",
			input:    "containerd://d4813c4da49cbaa50542f86bd077608e5d3da101efef52642346803c4d5a902b",
			expected: "d4813c4da49cbaa50542f86bd077608e5d3da101efef52642346803c4d5a902b",
		},
		{
			name:     "docker prefix is stripped",
			input:    "docker://abc123def456",
			expected: "abc123def456",
		},
		{
			name:     "crio prefix is stripped",
			input:    "cri-o://somecontainerid",
			expected: "somecontainerid",
		},
		{
			name:     "no prefix leaves the string unchanged",
			input:    "plaincontainerid",
			expected: "plaincontainerid",
		},
		{
			name:     "empty string returns empty string",
			input:    "",
			expected: "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			status := &corev1.ContainerStatus{ContainerID: tc.input}
			got := containerIDFromContainerStatus(status)
			require.Equal(t, tc.expected, got)
		})
	}
}

func TestAddContainerToPodView(t *testing.T) {
	podView := &agentv1.PodView{
		Containers: make(map[string]*agentv1.ContainerMeta),
	}

	containerID := "aabbcc112233"
	containerName := "my-container"
	status := &corev1.ContainerStatus{
		ContainerID: fmt.Sprintf("containerd://%s", containerID),
		Name:        containerName,
	}

	addContainerToPodView(status, podView)

	require.Len(t, podView.GetContainers(), 1)
	meta, ok := podView.GetContainers()[containerID]
	require.True(t, ok, "container should be keyed by the stripped ID")
	assert.Equal(t, containerID, meta.GetId())
	assert.Equal(t, containerName, meta.GetName())
	assert.Equal(t, uint64(0), meta.GetCgroupId())
}

func TestPodToView(t *testing.T) {
	tests := []struct {
		name         string
		pod          *corev1.Pod
		expectedView *agentv1.PodView
	}{
		{
			name: "simple pod",
			pod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "my-pod",
					Namespace: "my-namespace",
					UID:       types.UID("uid-1234"),
				},
				Status: corev1.PodStatus{
					ContainerStatuses: []corev1.ContainerStatus{
						{ContainerID: "containerd://cid1", Name: "main"},
					},
				},
			},
			expectedView: &agentv1.PodView{
				Meta: &agentv1.PodMeta{
					Id:        "uid-1234",
					Name:      "my-pod",
					Namespace: "my-namespace",
				},
				Containers: map[string]*agentv1.ContainerMeta{
					"cid1": {
						Id:   "cid1",
						Name: "main",
					},
				},
			},
		},
		{
			name: "static pod",
			pod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "static-pod",
					Namespace: "kube-system",
					UID:       types.UID("api-server-generated-uid"),
					Annotations: map[string]string{
						staticPodAnnotation: "mirror-uid",
					},
				},
				Status: corev1.PodStatus{
					InitContainerStatuses: []corev1.ContainerStatus{
						{ContainerID: "containerd://init1", Name: "init-container"},
					},
					ContainerStatuses: []corev1.ContainerStatus{
						{ContainerID: "containerd://main1", Name: "main-container"},
					},
					EphemeralContainerStatuses: []corev1.ContainerStatus{
						{ContainerID: "containerd://eph1", Name: "debug-container"},
					},
				},
			},
			expectedView: &agentv1.PodView{
				Meta: &agentv1.PodMeta{
					Id:        "mirror-uid",
					Name:      "static-pod",
					Namespace: "kube-system",
				},
				Containers: map[string]*agentv1.ContainerMeta{
					"init1": {
						Id:   "init1",
						Name: "init-container",
					},
					"main1": {
						Id:   "main1",
						Name: "main-container",
					},
					"eph1": {
						Id:   "eph1",
						Name: "debug-container",
					},
				},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			view := podToView(tc.pod)
			require.Equal(t, tc.expectedView, view)
		})
	}
}

func TestZeroOutUnrecoverableDetails(t *testing.T) {
	cache := map[nodeName][]*agentv1.PodView{
		"node-1": {
			{
				Meta: &agentv1.PodMeta{
					Id:           "pod-1",
					Name:         "my-pod",
					Namespace:    "default",
					WorkloadName: "my-deployment",
					WorkloadType: "Deployment",
					Labels:       map[string]string{"app": "test"},
				},
				Containers: map[string]*agentv1.ContainerMeta{
					"cid1": {Id: "cid1", Name: "c1", CgroupId: 42},
				},
			},
		},
	}

	zeroOutUnrecoverableDetails(cache)
	expectedPodView := &agentv1.PodView{
		Meta: &agentv1.PodMeta{
			Id:        "pod-1",
			Name:      "my-pod",
			Namespace: "default",
			// clean these fields
			WorkloadName: "",
			WorkloadType: "",
			Labels:       nil,
		},
		Containers: map[string]*agentv1.ContainerMeta{
			// clean the cgroupID
			"cid1": {Id: "cid1", Name: "c1", CgroupId: 0},
		},
	}

	podView := cache["node-1"][0]
	assert.Equal(t, expectedPodView, podView)
}

func podViewFixture(id, name, namespace string, containers map[string]string) *agentv1.PodView {
	c := make(map[string]*agentv1.ContainerMeta, len(containers))
	for cid, cname := range containers {
		c[cid] = &agentv1.ContainerMeta{Id: cid, Name: cname}
	}
	return &agentv1.PodView{
		Meta: &agentv1.PodMeta{
			Id:        id,
			Name:      name,
			Namespace: namespace,
		},
		Containers: c,
	}
}

func TestValidateAgentCache(t *testing.T) {
	podA := podViewFixture("uid-1", "pod-a", "default", map[string]string{"cid1": "c1"})
	podB := podViewFixture("uid-2", "pod-b", "default", map[string]string{"cid2": "c2"})
	nodeName1 := "node-1"
	nodeName2 := "node-2"

	tests := []struct {
		name           string
		agentCache     map[nodeName][]*agentv1.PodView
		expectedCache  map[nodeName][]*agentv1.PodView
		expectedOutput []string
	}{
		{
			name: "cache aligned",
			agentCache: map[nodeName][]*agentv1.PodView{
				nodeName1: {podA},
				nodeName2: {podB},
			},
			expectedCache: map[nodeName][]*agentv1.PodView{
				nodeName1: {podA},
				nodeName2: {podB},
			},
			expectedOutput: []string{"caches are aligned"},
		},
		{
			name: "node mismatch",
			agentCache: map[nodeName][]*agentv1.PodView{
				nodeName1: {podA},
			},
			expectedCache: map[nodeName][]*agentv1.PodView{
				nodeName1: {podA},
				nodeName2: {podB},
			},
			expectedOutput: []string{"Some nodes in the cluster don't have an agent cache", "caches are aligned"},
		},
		{
			name: "pod mismatch",
			agentCache: map[nodeName][]*agentv1.PodView{
				nodeName1: {podA},
			},
			expectedCache: map[nodeName][]*agentv1.PodView{
				nodeName1: {podB},
			},
			expectedOutput: []string{"caches are not aligned"},
		},
		{
			name:       "missing agent cache",
			agentCache: map[nodeName][]*agentv1.PodView{},
			expectedCache: map[nodeName][]*agentv1.PodView{
				nodeName1: {podB},
			},
			expectedOutput: []string{"no agent cache available"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			validateAgentCache(&buf, tc.agentCache, tc.expectedCache)
			for _, line := range tc.expectedOutput {
				assert.Contains(t, buf.String(), line, "output: %s", buf.String())
			}
		})
	}
}
