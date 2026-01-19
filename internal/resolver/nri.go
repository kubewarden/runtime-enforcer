package resolver

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/containerd/nri/pkg/api"
	"github.com/containerd/nri/pkg/stub"
	"github.com/neuvector/runtime-enforcer/internal/bpf"
	"github.com/neuvector/runtime-enforcer/internal/cgroups"
)

const (
	NRIReconnectTimeout = time.Second * 1
)

type plugin struct {
	stub       stub.Stub
	logger     *slog.Logger
	resolver   *Resolver
	cgroupRoot string
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
	containers []*api.Container,
) ([]*api.ContainerUpdate, error) {
	p.logger.InfoContext(ctx, "Synchronizing pod sandboxes", "podCount", len(pods))

	// TODO!: we need to check if we face a timeout.
	tmpSandboxes := make(map[string]map[ContainerID]*containerInfo)
	for _, container := range containers {
		if container == nil {
			// this is weird the NRI shouldn't send us empty containers
			p.logger.ErrorContext(ctx, "received empty container")
			continue
		}

		// TODO!: this should become a method
		if container.GetLinux() == nil {
			p.logger.ErrorContext(
				ctx,
				"received container without Linux info",
				"container-id",
				container.GetId(),
				"container-name",
				container.GetName(),
			)
			continue
		}

		parsedPath, err := ParseCgroupsPath(container.GetLinux().GetCgroupsPath())
		if err != nil {
			p.logger.ErrorContext(ctx, "failed to parse cgroup path",
				"path", container.GetLinux().GetCgroupsPath(),
				"container-id", container.GetId(),
				"container-name", container.GetName(),
				"error", err)
			continue
		}

		path := filepath.Join("/sys/fs/cgroup", parsedPath)

		cgroupID, err := cgroups.GetCgroupIDFromPath(path)
		if err != nil {
			p.logger.ErrorContext(ctx, "failed to get cgroup ID from path",
				"path", path,
				"container-id", container.GetId(),
				"container-name", container.GetName(),
				"error", err)
			continue
		}

		if _, exists := tmpSandboxes[container.GetPodSandboxId()]; !exists {
			tmpSandboxes[container.GetPodSandboxId()] = make(map[ContainerID]*containerInfo)
		}
		tmpSandboxes[container.GetPodSandboxId()][container.GetId()] = &containerInfo{
			cgID: cgroupID,
			name: container.GetName(),
		}
	}

	for _, pod := range pods {
		if pod == nil {
			// this is weird the NRI shouldn't send us empty pods
			p.logger.ErrorContext(ctx, "received empty pod")
			continue
		}

		// we first populate the state

		// we then check if there is the magic label and we need to apply a policy
	}

	// 1. For each container we get the cgroupID -> containerID -> podUID/podSandboxID
	// 2. For each pod we look at the labels and we see if there is a magic label and a policy to apply

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
	p.logger.DebugContext(
		ctx,
		"getting CreateContainer event",
		"container",
		container,
		"pod",
		pod,
	)

	// Note: currently kind is not supported, because the cgroup path received
	// from container runtime will miss a prefix like below, given that it runs in a cgroup ns.
	// /system.slice/docker-a52209e9e7f1202949c76bd58341da8a9d0e1e9aca9d389d5390fa503bf153e7.scope/...
	cgroupPath, err := ParseCgroupsPath(container.GetLinux().GetCgroupsPath())
	if err != nil {
		p.logger.ErrorContext(ctx, "failed to parse cgroup path", "error", err)
		return err
	}

	polID, ok := p.resolver.GetPolicyIDForContainer(pod, container)
	if !ok {
		p.logger.DebugContext(
			ctx,
			"no policy for the container",
			"cgroupPath",
			cgroupPath,
			"podName",
			pod.GetName(),
			"namespace",
			pod.GetNamespace(),
		)
		return nil
	}

	cgID, err := cgroups.GetCgroupIDFromPath(filepath.Join(p.cgroupRoot, cgroupPath))
	if err != nil {
		p.logger.ErrorContext(ctx, "failed to parse cgroup path", "error", err)
		return err
	}

	p.logger.InfoContext(
		ctx,
		"assigning policy via NRI",
		"namespace",
		pod.GetNamespace(),
		"podName",
		pod.GetName(),
		"containerName",
		container.GetName(),
		"cgroupPath",
		cgroupPath,
		"cgID",
		cgID,
		"policyID",
		polID,
	)

	if err = p.resolver.cgroupToPolicyMapUpdateFunc(polID, []CgroupID{cgID}, bpf.AddPolicyToCgroups); err != nil {
		p.logger.ErrorContext(ctx, "failed to update the cgroup path and policy id in cgPath ebpf map", "error", err)
		return err
	}

	return nil
}

// This would happen when container runtime restarts.
func (p *plugin) onClose() {
	p.logger.Info("Connection to the runtime lost, exiting...")
}

// StartNriPluginWithRetry creates a go routine and maintains a persistent connection with container runtime via NRI.
func (r *Resolver) StartNriPluginWithRetry(ctx context.Context, fn func(context.Context) error) {
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}
			err := fn(ctx)
			if err != nil {
				r.logger.Info("nri hook restarted", "error", err)
			}
			time.Sleep(NRIReconnectTimeout)
		}
	}()
}

func (r *Resolver) StartNriPlugin(ctx context.Context) error {
	var err error
	var cgroupRoot string
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	})).With("component", "nri-hook")

	cgroupRoot, err = cgroups.GetHostCgroupRoot()
	if err != nil {
		return fmt.Errorf("failed to get host cgroup root: %w", err)
	}
	p := &plugin{
		logger:     logger,
		resolver:   r,
		cgroupRoot: cgroupRoot,
	}

	// TODO!: not sure which hook are called

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
