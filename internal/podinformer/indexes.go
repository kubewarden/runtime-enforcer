package podinformer

import (
	"errors"
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
)

// Taken and adapted from: https://github.com/cilium/tetragon/blob/7f09bfd2ca0123867bc7c2ab0155ac8efbc29ede/pkg/watcher/pod.go#L17

const (
	containerIDLen = 15
	ContainerIdx   = "containers-ids"
	PodIdx         = "pod-ids"
)

var (
	errNoPod = errors.New("object is not a *corev1.Pod")
)

func ContainerIDKey(contID string) (string, error) {
	parts := strings.Split(contID, "//")
	const containerIDSplitParts = 2
	if len(parts) != containerIDSplitParts {
		return "", fmt.Errorf("unexpected containerID format, expecting 'docker://<name>', got %q", contID)
	}
	cid := parts[1]
	if len(cid) > containerIDLen {
		cid = cid[:containerIDLen]
	}
	return cid, nil
}

// ContainerIndexFunc index pod by container IDs.
func ContainerIndexFunc(obj interface{}) ([]string, error) {
	var containerIDs []string
	putContainer := func(fullContainerID string) error {
		if fullContainerID == "" {
			// This is expected if the container hasn't been started. This function
			// will get called again after the container starts, so we just need to
			// be patient.
			return nil
		}
		cid, err := ContainerIDKey(fullContainerID)
		if err != nil {
			return err
		}
		containerIDs = append(containerIDs, cid)
		return nil
	}

	pod, ok := obj.(*corev1.Pod)
	if !ok {
		return nil, fmt.Errorf("%w - found %T", errNoPod, obj)
	}

	for _, container := range pod.Status.InitContainerStatuses {
		err := putContainer(container.ContainerID)
		if err != nil {
			return nil, err
		}
	}
	for _, container := range pod.Status.ContainerStatuses {
		err := putContainer(container.ContainerID)
		if err != nil {
			return nil, err
		}
	}
	for _, container := range pod.Status.EphemeralContainerStatuses {
		err := putContainer(container.ContainerID)
		if err != nil {
			return nil, err
		}
	}
	return containerIDs, nil
}

func PodIndexFunc(obj interface{}) ([]string, error) {
	if pod, ok := obj.(*corev1.Pod); ok {
		return []string{string(pod.UID)}, nil
	}
	return nil, fmt.Errorf("PodIndexFunc: %w - found %T", errNoPod, obj)
}
