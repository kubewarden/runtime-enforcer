package resolver

import (
	"strings"

	v1 "k8s.io/api/core/v1"
)

type containerInfo struct {
	cgID CgroupID
	name ContainerName
	repo string
}

func containerIDFromContainerStatus(c *v1.ContainerStatus) string {
	ret := c.ContainerID
	if idx := strings.Index(ret, "://"); idx != -1 {
		ret = ret[idx+3:]
	}
	return ret
}

func podForAllContainers(pod *v1.Pod, fn func(c *v1.ContainerStatus)) {
	run := func(s []v1.ContainerStatus) {
		for i := range s {
			if s[i].State.Running != nil {
				fn(&s[i])
			}
		}
	}

	run(pod.Status.InitContainerStatuses)
	run(pod.Status.ContainerStatuses)
	run(pod.Status.EphemeralContainerStatuses)
}

func podContainersInfoWithoutCgroups(pod *v1.Pod) map[ContainerID]*containerInfo {
	ret := make(map[ContainerID]*containerInfo)
	podForAllContainers(pod, func(c *v1.ContainerStatus) {
		id := containerIDFromContainerStatus(c)
		repo := notFound
		// example ImageID: docker.io/library/ubuntu@sha256:aadf9a3f5eda81295050d13dabe851b26a67597e424a908f25a63f589dfed48f
		const imageIDRepoDigestParts = 2
		if parts := strings.Split(c.ImageID, "@"); len(parts) == imageIDRepoDigestParts {
			repo = parts[0]
		}
		ret[id] = &containerInfo{
			cgID: 0, // to be populated later
			name: c.Name,
			repo: repo,
		}
	})
	return ret
}
