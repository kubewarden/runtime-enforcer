package nri

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/containerd/nri/pkg/api"
	"github.com/kubewarden/runtime-enforcer/internal/bpf"
	"github.com/kubewarden/runtime-enforcer/internal/cgroups"
	"github.com/kubewarden/runtime-enforcer/internal/resolver"
	"github.com/kubewarden/runtime-enforcer/internal/types/policymode"
	"github.com/stretchr/testify/require"
)

const (
	benchPodCount         = 200
	benchContainersPerPod = 2
	benchMapMaxEntries    = 1 << 16
)

type benchMaps struct {
	cgTracker *ebpf.Map
	cgToPol   *ebpf.Map
}

func setupBenchMaps(b *testing.B) *benchMaps {
	b.Helper()

	require.Equal(b, 0, os.Geteuid())

	newMap := func() *ebpf.Map {
		m, mapErr := ebpf.NewMap(&ebpf.MapSpec{
			Type:       ebpf.Hash,
			KeySize:    8, // cgroupID
			ValueSize:  8, // trackerID / policyID
			MaxEntries: benchMapMaxEntries,
		})
		require.NoError(b, mapErr)
		b.Cleanup(func() { _ = m.Close() })
		return m
	}

	return &benchMaps{
		cgTracker: newMap(),
		cgToPol:   newMap(),
	}
}

func newBenchPlugin(b *testing.B, maps *benchMaps) *plugin {
	b.Helper()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	})).With("component", "nri-plugin")

	// The NRI benchmark path never attaches a policy, so these are never invoked.
	unusedBinaries := func(resolver.PolicyID, []string, bpf.PolicyValuesOperation) error {
		return errors.New("this function should be unused")
	}
	unusedMode := func(resolver.PolicyID, policymode.Mode, bpf.PolicyModeOperation) error {
		return errors.New("this function should be unused")
	}

	r, err := resolver.NewResolver(
		logger,
		func(cgID uint64, cgroupPath string) error {
			return bpf.UpdateCgTrackerMap(logger, maps.cgTracker, cgID, cgroupPath)
		},
		func(polID resolver.PolicyID, cgroupIDs []resolver.CgroupID, op bpf.CgroupPolicyOperation) error {
			return bpf.UpdateCgroupPolicy(maps.cgToPol, polID, cgroupIDs, op)
		},
		unusedBinaries,
		unusedMode,
	)
	require.NoError(b, err)

	return &plugin{
		logger:          logger,
		resolver:        r,
		resolveCgroupID: cgroupFromContainer,
	}
}

func removeCgroupTree(path string) error {
	entries, err := os.ReadDir(path)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.IsDir() {
			_ = removeCgroupTree(filepath.Join(path, entry.Name()))
		}
	}
	return os.Remove(path)
}

func createBenchCgroup(b *testing.B, name string) string {
	b.Helper()

	// All bench cgroups live under one fixed parent so leftovers can be
	// removed with a single directory if cleanup is interrupted.
	const parentName = "runtime-enforcer-bench-test"
	root := cgroups.GetCgroupResolutionPrefix()
	absParent := filepath.Join(root, parentName)
	absPath := filepath.Join(absParent, name)

	require.NoError(b, os.MkdirAll(absParent, 0o755))
	require.NoError(b, os.Mkdir(absPath, 0o755))
	b.Cleanup(func() {
		_ = os.Remove(absPath)
		_ = removeCgroupTree(absParent)
	})

	return filepath.Join("/", parentName, name)
}

func benchContainer(b *testing.B, pod *api.PodSandbox, name string) *api.Container {
	b.Helper()

	return &api.Container{
		Id:           name,
		Name:         name,
		PodSandboxId: pod.GetId(),
		Linux: &api.LinuxContainer{
			CgroupsPath: createBenchCgroup(b, name),
		},
	}
}

// benchTrackerCleanup returns a function that deletes the container's entry
// from the cgroup tracker map (no BPF programs loaded in benchmarks).
func benchTrackerCleanup(b *testing.B, maps *benchMaps, container *api.Container) func() {
	b.Helper()

	cgRoot := cgroups.GetCgroupResolutionPrefix()
	cgroupPath := filepath.Join(cgRoot, container.GetLinux().GetCgroupsPath())
	cgID, err := cgroups.GetCgroupIDFromPath(cgroupPath)
	require.NoError(b, err, "resolve cgroup ID")

	return func() {
		if err = maps.cgTracker.Delete(&cgID); err != nil {
			b.Fatalf("delete cgroup tracker entry: %v", err)
		}
	}
}

func buildSyncFixtures(b *testing.B, numPods, containersPerPod int) ([]*api.PodSandbox, []*api.Container) {
	b.Helper()

	pods := make([]*api.PodSandbox, numPods)
	containers := make([]*api.Container, 0, numPods*containersPerPod)

	for i := range numPods {
		podID := fmt.Sprintf("pod-%d", i)
		pods[i] = &api.PodSandbox{
			Id:        podID,
			Uid:       fmt.Sprintf("uid-%d", i),
			Name:      fmt.Sprintf("pod-%d", i),
			Namespace: "default",
			Labels:    map[string]string{"app": "demo"},
		}
		for j := range containersPerPod {
			name := fmt.Sprintf("container-%d-%d", i, j)
			containers = append(containers, benchContainer(b, pods[i], name))
		}
	}

	return pods, containers
}

func BenchmarkPluginSynchronize(b *testing.B) {
	maps := setupBenchMaps(b)
	pods, containers := buildSyncFixtures(b, benchPodCount, benchContainersPerPod)
	ctx := b.Context()

	b.ResetTimer()
	for range b.N {
		b.StopTimer()
		p := newBenchPlugin(b, maps)
		b.StartTimer()

		if _, err := p.Synchronize(ctx, pods, containers); err != nil {
			b.Fatalf("Synchronize: %v", err)
		}
	}
}

func BenchmarkPluginStartContainer(b *testing.B) {
	maps := setupBenchMaps(b)
	pod := testPodSandbox()
	ctx := b.Context()

	b.ResetTimer()
	for i := range b.N {
		b.StopTimer()
		p := newBenchPlugin(b, maps)
		container := benchContainer(b, pod, fmt.Sprintf("start-container-%d", i))
		cleanup := benchTrackerCleanup(b, maps, container)
		b.StartTimer()

		if err := p.StartContainer(ctx, pod, container); err != nil {
			b.Fatalf("StartContainer: %v", err)
		}

		b.StopTimer()
		cleanup()
	}
}

func BenchmarkPluginRemoveContainer(b *testing.B) {
	maps := setupBenchMaps(b)
	pod := testPodSandbox()
	ctx := b.Context()

	b.ResetTimer()
	for i := range b.N {
		b.StopTimer()
		p := newBenchPlugin(b, maps)
		container := benchContainer(b, pod, fmt.Sprintf("remove-container-%d", i))
		cleanup := benchTrackerCleanup(b, maps, container)

		if err := p.StartContainer(ctx, pod, container); err != nil {
			b.Fatalf("seed StartContainer: %v", err)
		}
		b.StartTimer()

		if err := p.RemoveContainer(ctx, pod, container); err != nil {
			b.Fatalf("RemoveContainer: %v", err)
		}

		b.StopTimer()
		cleanup()
	}
}
