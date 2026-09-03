package debugger

import (
	"bytes"
	"testing"

	agentv1 "github.com/kubewarden/runtime-enforcer/proto/agent/v1"
	"github.com/stretchr/testify/assert"
)

func agentContainerFixture(id, name string) *agentv1.ContainerMeta {
	return &agentv1.ContainerMeta{Id: id, Name: name}
}

func clusterContainerFixture(id, name string, terminated bool) *clusterContainerMeta {
	return &clusterContainerMeta{id: id, name: name, terminated: terminated}
}

func agentPodViewFixture(id, name, namespace string,
	containers map[containerID]*agentv1.ContainerMeta,
) *agentPodView {
	return &agentPodView{PodView: &agentv1.PodView{
		Meta: &agentv1.PodMeta{
			Id:        id,
			Name:      name,
			Namespace: namespace,
		},
		Containers: containers,
	}}
}

func clusterPodViewFixture(
	id, name, namespace string,
	containers map[containerID]*clusterContainerMeta,
) *clusterPodView {
	return &clusterPodView{
		id:         id,
		name:       name,
		namespace:  namespace,
		containers: containers,
	}
}

func TestComparePods(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		clusterPod   *clusterPodView
		agentPod     *agentPodView
		expectedDiff []string
	}{
		{
			name: "aligned pod",
			clusterPod: clusterPodViewFixture(
				"uid-1",
				"pod-1",
				"ns-1",
				map[containerID]*clusterContainerMeta{
					"cid1": clusterContainerFixture("cid1", "cname1", false),
				},
			),
			agentPod: agentPodViewFixture(
				"uid-1",
				"pod-1",
				"ns-1",
				map[containerID]*agentv1.ContainerMeta{
					"cid1": agentContainerFixture("cid1", "cname1"),
				},
			),
			expectedDiff: nil,
		},
		{
			name: "reports metadata and container mismatches",
			clusterPod: clusterPodViewFixture(
				"uid-1",
				"cluster-pod",
				"cluster-ns",
				map[containerID]*clusterContainerMeta{
					"cid1": clusterContainerFixture("cid1", "cluster-main", false),
					"cid2": clusterContainerFixture("cid2", "sidecar", false),
				},
			),
			agentPod: agentPodViewFixture(
				"uid-1",
				"agent-pod",
				"agent-ns",
				map[containerID]*agentv1.ContainerMeta{
					"cid1": agentContainerFixture("cid1", "agent-main"),
					"cid3": agentContainerFixture("cid3", "stale"),
				},
			),
			expectedDiff: []string{
				`cluster-ns/cluster-pod (uid-1): "namespace" mismatch: cluster="cluster-ns", agent="agent-ns"`,
				`cluster-ns/cluster-pod (uid-1): "name" mismatch: cluster="cluster-pod", agent="agent-pod"`,
				`cluster-ns/cluster-pod (uid-1): container "cid1": "name" mismatch: cluster="cluster-main", agent="agent-main"`,
				`cluster-ns/cluster-pod (uid-1): missing container "sidecar" ("cid2") in the agent cache`,
				`cluster-ns/cluster-pod (uid-1): container "stale" ("cid3") is only in the agent cache`,
			},
		},
		{
			name: "ignores terminated init container missing from agent cache",
			clusterPod: clusterPodViewFixture(
				"uid-2",
				"pod-1",
				"ns-1",
				map[containerID]*clusterContainerMeta{
					"cid1": clusterContainerFixture("cid1", "cname1", false),
					"cid2": clusterContainerFixture("cid2", "init-container", true),
				},
			),
			agentPod: agentPodViewFixture(
				"uid-2",
				"pod-1",
				"ns-1",
				map[containerID]*agentv1.ContainerMeta{
					"cid1": agentContainerFixture("cid1", "cname1"),
				},
			),
			expectedDiff: nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := comparePods(tc.clusterPod, tc.agentPod)
			assert.ElementsMatch(t, tc.expectedDiff, got)
		})
	}
}

func TestCompareCaches(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		clusterCache []*clusterPodView
		agentCache   []*agentPodView
		expectedDiff []string
	}{
		{
			name: "reports missing and unexpected pods",
			clusterCache: []*clusterPodView{
				clusterPodViewFixture(
					"uid-1",
					"pod-1",
					"ns-1",
					map[containerID]*clusterContainerMeta{
						"cid1": clusterContainerFixture("cid1", "cname1", false),
					},
				),
			},
			agentCache: []*agentPodView{
				agentPodViewFixture(
					"uid-2",
					"pod-2",
					"ns-2",
					map[containerID]*agentv1.ContainerMeta{
						"cid2": agentContainerFixture("cid2", "cname2"),
					},
				),
			},
			expectedDiff: []string{
				"pod ns-1/pod-1 (uid-1) is missing from the agent cache",
				"unexpected pod ns-2/pod-2 (uid-2) found in the agent cache",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := compareCaches(tc.clusterCache, tc.agentCache)
			assert.ElementsMatch(t, tc.expectedDiff, got)
		})
	}
}

func TestValidateCaches(t *testing.T) {
	t.Parallel()

	nodeName1 := "node-1"
	nodeName2 := "node-2"

	tests := []struct {
		name           string
		agentCache     map[nodeName][]*agentPodView
		clusterCache   map[nodeName][]*clusterPodView
		expectedOutput []string
	}{
		{
			name: "aligned caches",
			agentCache: map[nodeName][]*agentPodView{
				nodeName1: {
					agentPodViewFixture("uid-1", "pod-1", "ns-1", map[containerID]*agentv1.ContainerMeta{
						"cid1": agentContainerFixture("cid1", "cname1"),
					}),
				},
			},
			clusterCache: map[nodeName][]*clusterPodView{
				nodeName1: {
					clusterPodViewFixture("uid-1", "pod-1", "ns-1", map[containerID]*clusterContainerMeta{
						"cid1": clusterContainerFixture("cid1", "cname1", false),
					}),
				},
			},
			expectedOutput: []string{
				"=== Nodes in the cluster: 1, agent caches: 1.",
			},
		},
		{
			name: "found node differences",
			agentCache: map[nodeName][]*agentPodView{
				nodeName1: {
					agentPodViewFixture("uid-1", "pod-1", "ns-1", map[containerID]*agentv1.ContainerMeta{
						"cid1":             agentContainerFixture("cid1", "cname1"),
						"cid1-terminated1": agentContainerFixture("cid1-terminated1", "cname1"),
						// this is a terminated container still in the agent container cache but no more in the cluster
						"cid1-terminated2": agentContainerFixture("cid1-terminated2", "cname1"),
					}),
				},
			},
			clusterCache: map[nodeName][]*clusterPodView{
				nodeName1: {
					clusterPodViewFixture("uid-1", "pod-1", "ns-1", map[containerID]*clusterContainerMeta{
						"cid1":             clusterContainerFixture("cid1", "cname1", false),
						"cid1-terminated1": clusterContainerFixture("cid1-terminated1", "cname1", true),
					}),
				},
			},
			expectedOutput: []string{
				nodeMessage(nodeName1, foundNodeDifferences),
				`ns-1/pod-1 (uid-1): container "cname1" ("cid1-terminated2") is only in the agent cache`,
				"==== Agent cache dump (1 pods)",
			},
		},
		{
			name:       "missing agent cache",
			agentCache: map[nodeName][]*agentPodView{},
			clusterCache: map[nodeName][]*clusterPodView{
				nodeName1: {
					clusterPodViewFixture("uid-1", "pod-1", "ns-1", map[containerID]*clusterContainerMeta{
						"cid1": clusterContainerFixture("cid1", "cname1", false),
					}),
				},
			},
			expectedOutput: []string{
				nodeMessage(nodeName1, noAgentCache),
			},
		},
		{
			name: "unexpected agent cache",
			agentCache: map[nodeName][]*agentPodView{
				nodeName2: {
					agentPodViewFixture("uid-2", "pod-2", "ns-2", map[containerID]*agentv1.ContainerMeta{
						"cid2": agentContainerFixture("cid2", "cname2"),
					}),
				},
			},
			clusterCache: map[nodeName][]*clusterPodView{},
			expectedOutput: []string{
				nodeMessage(nodeName2, unexpectedAgentCache),
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var buf bytes.Buffer
			validateCaches(&buf, tc.agentCache, tc.clusterCache)
			out := buf.String()
			for _, line := range tc.expectedOutput {
				assert.Contains(t, out, line, "output: %s", out)
			}
		})
	}
}
