package debugger

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"sort"
	"time"

	"github.com/kubewarden/runtime-enforcer/internal/grpcexporter"
	agentv1 "github.com/kubewarden/runtime-enforcer/proto/agent/v1"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/cache"
)

type nodeName = string

type nodeMsg string

const (
	noAgentCache         nodeMsg = "no agent cache available"
	foundNodeDifferences nodeMsg = "found differences"
	unexpectedAgentCache nodeMsg = "unexpected agent cache"
)

func printAgentCache(w io.Writer,
	agentCache []*agentPodView) {
	fmt.Fprintf(w, "==== Agent cache dump (%d pods)\n", len(agentCache))
	for _, view := range agentCache {
		fmt.Fprintf(w, "- pod: %s\n", view)
		for containerID, containerMeta := range view.GetContainers() {
			fmt.Fprintf(w, "-- container: (id=%s) %s\n", containerID, containerMeta.GetName())
		}
	}
	fmt.Fprintln(w)
}

func nodeMessage(nodeName string, msg nodeMsg) string {
	return fmt.Sprintf("\n=== Node %q: %s\n", nodeName, msg)
}

func printNodeMessage(w io.Writer, nodeName string, msg nodeMsg) {
	fmt.Fprint(w, nodeMessage(nodeName, msg))
}

func validateCaches(w io.Writer,
	agentCaches map[nodeName][]*agentPodView,
	clusterCaches map[nodeName][]*clusterPodView) {
	fmt.Fprintf(w, "== Caches diff with cluster state: %v ==\n", time.Now())

	// These could be different when the runtime enforcer is not installed on some agents.
	fmt.Fprintf(
		w,
		"=== Nodes in the cluster: %d, agent caches: %d.\n",
		len(clusterCaches),
		len(agentCaches),
	)

	for nodeName, clusterCache := range clusterCaches {
		// Skip nodes without an agent cache
		agentCache, ok := agentCaches[nodeName]
		if !ok {
			printNodeMessage(w, nodeName, noAgentCache)
			continue
		}

		sort.Slice(agentCache, func(i, j int) bool {
			return agentCache[i].sortKey() < agentCache[j].sortKey()
		})
		sort.Slice(clusterCache, func(i, j int) bool {
			return clusterCache[i].sortKey() < clusterCache[j].sortKey()
		})

		differences := compareCaches(clusterCache, agentCache)
		// If there is at least a difference on the node level, we print the full agent cache.
		if len(differences) > 0 {
			printNodeMessage(w, nodeName, foundNodeDifferences)
			for _, difference := range differences {
				fmt.Fprintf(w, "- %s\n", difference)
			}
			printAgentCache(w, agentCaches[nodeName])
		}
	}

	for nodeName := range agentCaches {
		if _, ok := clusterCaches[nodeName]; !ok {
			printNodeMessage(w, nodeName, unexpectedAgentCache)
			printAgentCache(w, agentCaches[nodeName])
		}
	}
}

func compareCaches(clusterCache []*clusterPodView, agentCache []*agentPodView) []string {
	clusterIdx := 0
	agentIdx := 0
	differences := make([]string, 0)

	for clusterIdx < len(clusterCache) && agentIdx < len(agentCache) {
		clusterPod := clusterCache[clusterIdx]
		cachePod := agentCache[agentIdx]

		clusterKey := clusterPod.sortKey()
		cacheKey := cachePod.sortKey()

		switch {
		case clusterKey < cacheKey:
			differences = append(differences, missingPodFromAgentCache(clusterPod))
			clusterIdx++
		case cacheKey < clusterKey:
			differences = append(differences, unexpectedPodInAgentCache(cachePod))
			agentIdx++
		default:
			differences = append(differences, comparePods(clusterPod, cachePod)...)
			clusterIdx++
			agentIdx++
		}
	}

	for ; clusterIdx < len(clusterCache); clusterIdx++ {
		differences = append(
			differences,
			missingPodFromAgentCache(clusterCache[clusterIdx]),
		)
	}

	for ; agentIdx < len(agentCache); agentIdx++ {
		differences = append(
			differences,
			unexpectedPodInAgentCache(agentCache[agentIdx]),
		)
	}
	return differences
}

func missingPodFromAgentCache(clusterPod *clusterPodView) string {
	return fmt.Sprintf("pod %s is missing from the agent cache", clusterPod)
}

func unexpectedPodInAgentCache(agentPod *agentPodView) string {
	return fmt.Sprintf("unexpected pod %s found in the agent cache", agentPod)
}

func fieldMismatch(fieldName, clusterValue, agentValue string) string {
	return fmt.Sprintf("%q mismatch: cluster=%q, agent=%q", fieldName, clusterValue, agentValue)
}

func containerNameMismatch(containerID, clusterValue, agentValue string) string {
	return fmt.Sprintf("container %q: %s", containerID, fieldMismatch("name", clusterValue, agentValue))
}

func comparePods(clusterPod *clusterPodView, cachePod *agentPodView) []string {
	differences := make([]string, 0)

	// At the moment we don't compare
	// - WorkloadName, WorkloadType -> we don't recover them from the ownerReference when we get the pod from the informer.
	// - Labels -> we don't get the full set from the agent so they won't match the ones in the cluster.
	// - CgroupID -> we don't recover it when we get the pod from the informer.

	// Namespace
	if clusterPod.getNamespace() != cachePod.getNamespace() {
		differences = append(
			differences,
			fieldMismatch("namespace", clusterPod.getNamespace(), cachePod.getNamespace()),
		)
	}

	if clusterPod.getName() != cachePod.getName() {
		differences = append(
			differences,
			fieldMismatch("name", clusterPod.getName(), cachePod.getName()),
		)
	}

	// Containers
	for containerID, clusterContainer := range clusterPod.getContainers() {
		cacheContainer, ok := cachePod.getContainers()[containerID]
		if !ok {
			if clusterContainer.terminated {
				// if the container is terminated, we can skip it
				continue
			}

			differences = append(
				differences,
				fmt.Sprintf("missing container %q (%q) in the agent cache", clusterContainer.name, containerID),
			)
			continue
		}

		if clusterContainer.name != cacheContainer.GetName() {
			differences = append(
				differences,
				containerNameMismatch(containerID, clusterContainer.name, cacheContainer.GetName()),
			)
		}
	}

	for containerID, cacheContainer := range cachePod.getContainers() {
		if _, ok := clusterPod.getContainers()[containerID]; ok {
			continue
		}

		// These will be very likely old terminated containers left in the cache because we still need to receive the RemoveContainer event.
		// For now we leave them because we want to compare the real status of the cache also to debug possible memory issues/leakage.
		// In the future we could put in place heuristics to ignore these containers by looking if there is already a container with that name in the pod.
		differences = append(
			differences,
			fmt.Sprintf("container %q (%q) is only in the agent cache", cacheContainer.GetName(), containerID),
		)
	}

	podStr := clusterPod.String()
	for i, diff := range differences {
		differences[i] = fmt.Sprintf("%s: %s", podStr, diff)
	}

	return differences
}

func ValidatePodCacheIntegrity(ctx context.Context,
	logger *slog.Logger,
	c cache.Cache,
	pool *grpcexporter.AgentClientPool,
) error {
	clients, err := pool.UpdatePool(ctx, c)
	if err != nil {
		return fmt.Errorf("failed to update agent client pool: %w", err)
	}

	// Build the agent cache per node from GRPC.
	agentCaches := make(map[nodeName][]*agentPodView)
	for nodeName, client := range clients {
		if client == nil {
			logger.ErrorContext(ctx, "Agent client is nil", "node", nodeName)
			continue
		}

		var podCacheList []*agentv1.PodView
		podCacheList, err = client.ListPodCache(ctx)
		if err != nil {
			pool.MarkStaleAgentClient(nodeName)
			logger.ErrorContext(ctx, "Failed to list pod cache", "node", nodeName, "error", err)
			continue
		}
		agentCaches[nodeName] = newAgentPodViews(podCacheList)
	}

	// Build the expected cache from the cluster pod list.
	clusterCaches := make(map[nodeName][]*clusterPodView)
	var podList corev1.PodList
	if err = c.List(ctx, &podList); err != nil {
		return fmt.Errorf("failed to list pods in the cluster: %w", err)
	}
	for i := range podList.Items {
		pod := &podList.Items[i]

		switch pod.Status.Phase {
		// We can see at least a case in which a failed pod won't be present in agent cache,
		// but only in the cluster one -> if during a StartContainer we prevent the container startup,
		// we won't see the pod in our agent cache, but we will see it in the cluster as failed.
		// This could cause a difference between the agent cache and the cluster representation.
		// On the other side, we can also see the opposite case, where a failed pod is present in our cache
		// but we wouldn't find it in our cluster representation because we skip it here...
		// Since the second case should be more common than the first one, we add failed pods to the cache
		case corev1.PodRunning, corev1.PodSucceeded, corev1.PodFailed:
			clusterCaches[pod.Spec.NodeName] = append(
				clusterCaches[pod.Spec.NodeName],
				newClusterPodView(pod),
			)
		case corev1.PodPending:
		case corev1.PodUnknown:
		default:
			continue
		}
	}

	// Print diff between expected and actual cache per node.
	validateCaches(os.Stdout, agentCaches, clusterCaches)
	return nil
}
