package nri

import (
	"context"
	"fmt"
	"log/slog"

	retry "github.com/avast/retry-go/v4"
	"github.com/containerd/nri/pkg/api"
	"github.com/containerd/nri/pkg/stub"
	"github.com/rancher-sandbox/runtime-enforcer/api/v1alpha1"
	"github.com/rancher-sandbox/runtime-enforcer/internal/podworkload"
	"github.com/rancher-sandbox/runtime-enforcer/internal/resolver"
	"github.com/rancher-sandbox/runtime-enforcer/internal/types/workloadkind"
)

type plugin struct {
	stub            stub.Stub
	logger          *slog.Logger
	resolver        *resolver.Resolver
	lastErr         error
	failOpen        bool
	ociHookSocket   string
	ociHookBin      string
	resolveCgroupID func(container *api.Container) (resolver.CgroupID, string, error)
}

// podLogger returns a logger pre-enriched with the pod fields.
func (p *plugin) podLogger(pod *api.PodSandbox) *slog.Logger {
	policy := "none"
	labels := pod.GetLabels()
	if labels != nil && labels[v1alpha1.PolicyLabelKey] != "" {
		policy = labels[v1alpha1.PolicyLabelKey]
	}
	return p.logger.With(
		slog.Group("pod",
			"name", pod.GetName(),
			"namespace", pod.GetNamespace(),
			"uid", pod.GetUid(),
			"policy", policy,
		),
	)
}

// containerLogger returns a logger pre-enriched with the pod and container fields.
func (p *plugin) containerLogger(pod *api.PodSandbox, container *api.Container) *slog.Logger {
	return p.podLogger(pod).With(
		slog.Group("container",
			"name", container.GetName(),
			"id", container.GetId(),
		),
	)
}

func (p *plugin) getWorkloadInfoAndLog(ctx context.Context, pod *api.PodSandbox) (string, workloadkind.Kind) {
	workloadName, workloadKind, truncated := podworkload.GetTruncatedWorkloadInfo(pod.GetName(), pod.GetLabels())
	if truncated {
		p.podLogger(pod).WarnContext(ctx, "Detected truncated workload name",
			"workloadName", workloadName,
			"workloadKind", workloadKind,
		)
	}
	return workloadName, workloadKind
}

func podSandboxToPodMeta(pod *api.PodSandbox, workloadName string, workloadKind workloadkind.Kind) resolver.PodMeta {
	return resolver.PodMeta{
		// K8s static pods are created by the Kubelet with a pod uid that is different from the one
		// assigned by the API server. The pod uid created by the kubelet will be put in the `kubernetes.io/config.hash`
		// annotations of the pod. Example:
		//
		// apiVersion: v1
		// kind: Pod
		// metadata:
		//   annotations:
		//     kubernetes.io/config.hash: b3cae5f340c39f8cecdf0bddc7a4cdf1 // UID assigned by the kubelet
		//     kubernetes.io/config.mirror: b3cae5f340c39f8cecdf0bddc7a4cdf1
		//   name: kube-scheduler-kind-control-plane
		//   namespace: kube-system
		//   uid: a2533bd3-3631-48b3-88e4-2d139233d057 // UID assigned by the API server
		//
		// We cannot recover the UID assigned by the API-server from the NRI context.
		ID:           pod.GetUid(),
		Name:         pod.GetName(),
		Namespace:    pod.GetNamespace(),
		WorkloadName: workloadName,
		WorkloadType: string(workloadKind),
		Labels:       pod.GetLabels(),
	}
}

// Synchronize synchronizes the state of the NRI plugin with the current state of the pods and containers.
func (p *plugin) Synchronize(
	ctx context.Context,
	pods []*api.PodSandbox,
	containers []*api.Container,
) ([]*api.ContainerUpdate, error) {
	p.logger.InfoContext(ctx, "Synchronizing pod sandboxes",
		"podCount", len(pods),
		"containerCount", len(containers),
	)

	// we store the container for now and we associate them later with the pod sandbox
	tmpSandboxes := make(map[string]map[resolver.ContainerID]resolver.ContainerInput)
	for _, container := range containers {
		// We need to take also the cgroupPath in synchronize because it is possible that we already have nested containers and we need to iterate over them inside the resolver.
		cgroupID, cgroupPath, err := p.resolveCgroupID(container)
		if err != nil {
			// When this happens, we can't retrieve the cgroup ID in the target system.
			// This is a critical error.
			//
			// By returning a retry.Unrecoverable error, we allow our retry logic in Handler.Start() to
			// skip the retries and abort immediately.
			p.lastErr = retry.Unrecoverable(fmt.Errorf("failed to synchronize NRI plugin: %w", err))

			// Container runtime will log this. We log here too for convenience.
			p.logger.ErrorContext(ctx, "failed to synchronize NRI plugin",
				"error", err)
			return nil, p.lastErr
		}

		// Populate the sandbox map
		if _, exists := tmpSandboxes[container.GetPodSandboxId()]; !exists {
			tmpSandboxes[container.GetPodSandboxId()] = make(map[resolver.ContainerID]resolver.ContainerInput)
		}
		tmpSandboxes[container.GetPodSandboxId()][container.GetId()] = resolver.ContainerInput{
			ContainerMeta: resolver.ContainerMeta{
				CgroupID: cgroupID,
				Name:     container.GetName(),
				ID:       container.GetId(),
			},
			CgroupPath: cgroupPath,
		}
	}

	for _, pod := range pods {
		if pod == nil {
			// safety check, this should never happen
			p.logger.ErrorContext(ctx, "received empty pod")
			continue
		}

		podLogger := p.podLogger(pod)
		containers, ok := tmpSandboxes[pod.GetId()]
		if !ok {
			// no containers found for pod. There are at least 2 possible reasons for this:
			// 1. the pod sandbox is just created, so there are no containers yet.
			// 2. the pod is in terminating state and exiting containers are not sent.
			// See https://github.com/containerd/containerd/blob/1677a17964311325ed1c31e2c0a3589ce6d5c30d/pkg/nri/nri.go#L446 and https://github.com/containerd/containerd/blob/ff6324c9532b60137729a0e75fc589a2b20242b7/pkg/cri/nri/nri_api_linux.go#L393.
			// In both cases there is no reason to add the pod sandbox to the cache,
			// since we have no containers.
			podLogger.InfoContext(ctx, "received pod sandbox with no containers")
			continue
		}

		workloadName, workloadKind := p.getWorkloadInfoAndLog(ctx, pod)
		podData := resolver.PodInput{
			Meta:       podSandboxToPodMeta(pod, workloadName, workloadKind),
			Containers: containers,
		}

		// Add also the full list for debugging purpose
		podLogger.DebugContext(ctx, "Synchronize pod with containers",
			"containers", containers,
		)
		if err := p.resolver.AddPodContainerFromNri(podData); err != nil {
			// This could be recoverable. Returning an error so we can retry.
			podLogger.ErrorContext(ctx, "failed to add pod container from NRI", "error", err)
			return nil, fmt.Errorf("failed to add pod container from NRI: %w", err)
		}
	}
	// Mark resolver as synchronized, so old agent can be safely removed.
	p.resolver.NRISynchronized()
	p.logger.InfoContext(ctx, "Pod sandboxes synchronized")
	return nil, nil
}

// CreateContainer injects an OCI createRuntime hook so runc invokes oci-hook before container init.
func (p *plugin) CreateContainer(
	ctx context.Context,
	pod *api.PodSandbox,
	container *api.Container,
) (*api.ContainerAdjustment, []*api.ContainerUpdate, error) {
	if p.ociHookSocket == "" || p.ociHookBin == "" {
		return nil, nil, nil
	}

	p.containerLogger(pod, container).DebugContext(ctx, "CreateContainer: injecting OCI createRuntime hook")

	adjust := &api.ContainerAdjustment{}
	adjust.AddHooks(&api.Hooks{
		CreateRuntime: []*api.Hook{
			{
				Path: p.ociHookBin,
				Args: []string{p.ociHookBin, "-socket", p.ociHookSocket, "createRuntime"},
			},
		},
	})
	return adjust, nil, nil
}

func (p *plugin) StartContainer(
	ctx context.Context,
	pod *api.PodSandbox,
	container *api.Container,
) error {
	containerLogger := p.containerLogger(pod, container)
	containerLogger.InfoContext(ctx, "Starting container")

	handleError := func(reason string, err error) error {
		logger := containerLogger.With(
			"reason", reason,
			"error", err,
		)
		if p.failOpen {
			logger.WarnContext(ctx, "container is starting WITHOUT enforcement due to nriFailopen=true")
			return nil
		}
		nriErr := fmt.Errorf(
			"%s: %w. Runtime-enforcer has prevented the container '%s/%s' from starting. To change this behavior, set agent.nriFailopen=true in the helm chart",
			reason,
			err,
			pod.GetName(),
			container.GetName(),
		)

		logger.ErrorContext(ctx, nriErr.Error())
		return nriErr
	}

	// Here we can ignore the cgroupPath because the container is not yet running so we cannot have nested cgroups.
	cgroupID, _, err := p.resolveCgroupID(container)
	if err != nil {
		// this should never happen because we've succeeded before in Synchronize() call.
		// When this happens, it indicates a serious inconsistency in the system.
		return handleError("failed to get cgroup ID from container", err)
	}

	workloadName, workloadKind := p.getWorkloadInfoAndLog(ctx, pod)
	podData := resolver.PodInput{
		Meta: podSandboxToPodMeta(pod, workloadName, workloadKind),
		Containers: map[resolver.ContainerID]resolver.ContainerInput{
			container.GetId(): {
				ContainerMeta: resolver.ContainerMeta{
					CgroupID: cgroupID,
					Name:     container.GetName(),
					ID:       container.GetId(),
				},
				CgroupPath: "",
			},
		},
	}

	if err = p.resolver.AddPodContainerFromNri(podData); err != nil {
		return handleError("failed to add pod container from NRI", err)
	}
	return nil
}

// RemoveContainer removes a container from the resolver when it is removed from the pod sandbox.
// The idea is that we want to keep the container alive in our cache as much as we can because ebpf asynchronously sends events,
// so it's possible that even if the container is stopped, we are still receiving some old events, and we want to enrich them.
// That's the reason why we preferred `RemoveContainer` over `StopContainer`.
func (p *plugin) RemoveContainer(ctx context.Context, pod *api.PodSandbox, container *api.Container) error {
	containerLogger := p.containerLogger(pod, container)
	containerLogger.InfoContext(ctx, "Removing container")
	if err := p.resolver.RemovePodContainerFromNri(pod.GetUid(), container.GetId()); err != nil {
		containerLogger.ErrorContext(ctx, "failed to remove pod container from cache",
			"error", err,
		)
	}
	return nil
}
