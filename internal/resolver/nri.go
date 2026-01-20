package resolver

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"time"

	"github.com/containerd/nri/pkg/api"
	"github.com/containerd/nri/pkg/stub"
)

const (
	NRIReconnectWaitTime = time.Second * 1
	NRIConnectTimeout    = time.Second * 3
)

type plugin struct {
	stub     stub.Stub
	logger   *slog.Logger
	resolver *Resolver
	// mask       stub.EventMask
}

// type PodSandboxID string

// type containerState struct {
// 	name string
// 	// we don't have the image repo
// 	podSandbox string
// }

// type newPodState struct {
// 	podID        string
// 	namespace    string
// 	name         string
// 	workloadName string
// 	workloadType string
// 	labels       labels.Labels
// }

// var (
// 	cgroupIDToContainerID map[CgroupID]PodSandboxID
// 	podCache              map[PodSandboxID]*newPodState
// )

func (p *plugin) Synchronize(
	ctx context.Context,
	pods []*api.PodSandbox,
	_ []*api.Container,
) ([]*api.ContainerUpdate, error) {
	p.logger.InfoContext(ctx, "Synchronizing pod sandboxes", "podCount", len(pods))

	// TODO!: we need to check if we face a timeout.
	// tmpSandboxes := make(map[string]map[ContainerID]*containerInfo)
	// for _, container := range containers {
	// 	if container == nil {
	// 		// this is weird the NRI shouldn't send us empty containers
	// 		p.logger.ErrorContext(ctx, "received empty container")
	// 		continue
	// 	}

	// 	// TODO!: this should become a method
	// 	if container.GetLinux() == nil {
	// 		p.logger.ErrorContext(
	// 			ctx,
	// 			"received container without Linux info",
	// 			"container-id",
	// 			container.GetId(),
	// 			"container-name",
	// 			container.GetName(),
	// 		)
	// 		continue
	// 	}

	// 	// Parse the cgroup path
	// 	parsedPath, err := ParseCgroupsPath(container.GetLinux().GetCgroupsPath())
	// 	if err != nil {
	// 		p.logger.ErrorContext(ctx, "failed to parse cgroup path",
	// 			"path", container.GetLinux().GetCgroupsPath(),
	// 			"container-id", container.GetId(),
	// 			"container-name", container.GetName(),
	// 			"error", err)
	// 		continue
	// 	}

	// 	cgRoot, _ := cgroups.GetHostCgroupRoot()
	// 	path := filepath.Join(cgRoot, parsedPath)

	// 	// Get the cgroup ID
	// 	cgroupID, err := cgroups.GetCgroupIDFromPath(path)
	// 	if err != nil {
	// 		p.logger.ErrorContext(ctx, "failed to get cgroup ID from path",
	// 			"path", path,
	// 			"container-id", container.GetId(),
	// 			"container-name", container.GetName(),
	// 			"error", err)
	// 		continue
	// 	}

	// 	// Update the ebpf map
	// 	if err = p.resolver.cgTrackerUpdateFunc(cgroupID, path); err != nil {
	// 		p.logger.ErrorContext(ctx, "failed to update cgroup tracker map",
	// 			"path", path,
	// 			"container-id", container.GetId(),
	// 			"container-name", container.GetName(),
	// 			"error", err)
	// 		continue
	// 	}

	// 	// Populate the sandbox map
	// 	if _, exists := tmpSandboxes[container.GetPodSandboxId()]; !exists {
	// 		tmpSandboxes[container.GetPodSandboxId()] = make(map[ContainerID]*containerInfo)
	// 	}
	// 	tmpSandboxes[container.GetPodSandboxId()][container.GetId()] = &containerInfo{
	// 		cgID: cgroupID,
	// 		name: container.GetName(),
	// 	}
	// }

	// for _, pod := range pods {
	// 	if pod == nil {
	// 		// this is weird the NRI shouldn't send us empty pods
	// 		p.logger.ErrorContext(ctx, "received empty pod")
	// 		continue
	// 	}

	// 	// sanity check
	// 	if _, exists := p.resolver.podCache[pod.GetUid()]; exists {
	// 		p.logger.ErrorContext(ctx, "pod already exists in cache during synchronization", "uid", pod.GetUid())
	// 	}

	// 	PodState := &PodState{
	// 		// could be also a nil pointer
	// 		containers: tmpSandboxes[pod.GetId()],
	// 		info: &podInfo{
	// 			podID:     pod.GetUid(),
	// 			namespace: pod.GetNamespace(),
	// 			name:      pod.GetName(),
	// 			labels:    pod.GetLabels(),
	// 			// no workload-name and type for now...
	// 		},
	// 	}

	// 	// we first populate the pod cache
	// 	p.resolver.podCache[pod.GetUid()] = PodState

	// 	// we populate the cgroup ID to pod
	// 	for _, info := range PodState.containers {
	// 		p.resolver.cgroupIDToPodID[info.cgID] = pod.GetUid()

	// 		// TODO!: this is suboptimal we already have the name of the policy we should use it.

	// 		polID, ok := p.resolver.TmpGetPolicyIDForContainer(pod, info.name)
	// 		if !ok {
	// 			continue
	// 		}

	// 		if err := p.resolver.cgroupToPolicyMapUpdateFunc(polID, []CgroupID{info.cgID}, bpf.AddPolicyToCgroups); err != nil {
	// 			p.logger.ErrorContext(
	// 				ctx,
	// 				"failed to update the cgroup path and policy id in cgPath ebpf map",
	// 				"error",
	// 				err,
	// 			)
	// 			continue
	// 		}
	// 	}
	// }
	return nil, nil
}

// func (p *plugin) RunPodSandbox(_ context.Context, pod *api.PodSandbox) error {
// 	return nil
// }

// func (p *plugin) RemovePodSandbox(_ context.Context, pod *api.PodSandbox) error {
// 	return nil
// }

// func (p *plugin) RemoveContainer(_ context.Context, pod *api.PodSandbox, container *api.Container) error {
// 	return nil
// }

func (p *plugin) StartContainer(
	ctx context.Context,
	pod *api.PodSandbox,
	container *api.Container,
) error {
	var err error
	defer func() {
		if err != nil {
			p.logger.ErrorContext(ctx, "failed to respond StartContainer hook", "error", err)
		}
	}()

	p.logger.DebugContext(
		ctx,
		"getting CreateContainer event",
		"container",
		container,
		"pod",
		pod,
	)

	err = p.resolver.AddPodFromNRI(ctx, pod, container)
	if err != nil {
		return fmt.Errorf("failed to add pod from NRI: %w", err)
	}

	return nil
}

// This would happen when container runtime restarts.
func (p *plugin) onClose() {
	p.logger.Info("Connection to the runtime lost...")
}

// StartNriPluginWithRetry creates a go routine and maintains a persistent connection with container runtime via NRI.
func (r *Resolver) StartNriPluginWithRetry(ctx context.Context, fn func(context.Context) error) error {
	d := net.Dialer{
		Timeout: NRIConnectTimeout,
	}
	conn, err := d.DialContext(ctx, "unix", r.nriSocketPath)
	if err != nil {
		return err
	}
	defer conn.Close()

	// now we know that NRI socket is available and listening.
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}
			err = fn(ctx)
			if err != nil {
				r.logger.Info("nri hook restarted", "error", err)
			}
			time.Sleep(NRIReconnectWaitTime)
		}
	}()
	return nil
}

func (r *Resolver) StartNriPlugin(ctx context.Context) error {
	var err error
	logger := r.logger.WithGroup("nri-hook")

	p := &plugin{
		logger:   logger,
		resolver: r,
	}

	opts := []stub.Option{
		stub.WithPluginIdx(r.nriPluginIndex),
		stub.WithSocketPath(r.nriSocketPath),
		stub.WithOnClose(p.onClose),
	}

	p.stub, err = stub.New(p, opts...)
	if err != nil {
		return fmt.Errorf("failed to create NRI plugin stub: %w", err)
	}

	err = p.stub.Run(ctx)
	if err != nil {
		return fmt.Errorf("NRI plugin exited with error: %w", err)
	}
	return nil
}
