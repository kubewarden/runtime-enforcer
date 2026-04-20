package nri

import (
	"errors"
	"io"
	"log/slog"
	"testing"

	"github.com/containerd/nri/pkg/api"
	"github.com/rancher-sandbox/runtime-enforcer/internal/resolver"
	"github.com/rancher-sandbox/runtime-enforcer/internal/types/workloadkind"
	"github.com/stretchr/testify/require"
)

func newTestPlugin(
	t *testing.T,
	failOpen bool,
	cgroupToReturn resolver.CgroupID,
	ociHookSocket, ociHookBin string,
) *plugin {
	t.Helper()

	return &plugin{
		logger:        slog.New(slog.NewTextHandler(io.Discard, nil)),
		resolver:      resolver.NewTestResolver(t),
		failOpen:      failOpen,
		ociHookBin:    ociHookBin,
		ociHookSocket: ociHookSocket,
		resolveCgroupID: func(*api.Container) (resolver.CgroupID, string, error) {
			if cgroupToReturn != 0 {
				return cgroupToReturn, "", nil
			}
			return 0, "", errors.New("lookup failed")
		},
	}
}

func testPodSandbox() *api.PodSandbox {
	return &api.PodSandbox{
		Id:          "sandbox-id",
		Uid:         "pod-uid",
		Name:        "demo-pod",
		Namespace:   "demo-ns",
		Labels:      map[string]string{"app": "demo"},
		Annotations: map[string]string{},
	}
}

func testContainer() *api.Container {
	return &api.Container{
		Id:   "container-id",
		Name: "app",
		Linux: &api.LinuxContainer{
			CgroupsPath: "/unused/by/mock",
		},
	}
}

func TestPluginStartContainer(t *testing.T) {
	t.Run("adds container to resolver on success", func(t *testing.T) {
		pod := testPodSandbox()
		container := testContainer()

		p := newTestPlugin(t, false, 100, "", "")

		err := p.StartContainer(t.Context(), pod, container)
		require.NoError(t, err)

		containerView, err := p.resolver.GetContainerView(100)
		require.NoError(t, err)
		require.Equal(t, &resolver.ContainerView{
			PodMeta: resolver.PodMeta{
				ID:           pod.GetUid(),
				Name:         pod.GetName(),
				Namespace:    pod.GetNamespace(),
				WorkloadName: pod.GetName(),
				WorkloadType: string(workloadkind.Pod),
				Labels:       pod.GetLabels(),
			},
			Meta: resolver.ContainerMeta{
				ID:       container.GetId(),
				Name:     container.GetName(),
				CgroupID: 100,
			},
		}, containerView)
	})

	t.Run("returns nil in fail-open mode when cgroup lookup fails", func(t *testing.T) {
		p := newTestPlugin(t, true, 0, "", "")
		pod := testPodSandbox()
		container := testContainer()

		err := p.StartContainer(t.Context(), pod, container)
		require.NoError(t, err)
		require.Empty(t, p.resolver.PodCacheSnapshot())
	})

	t.Run("returns wrapped error in fail-closed mode when cgroup lookup fails", func(t *testing.T) {
		p := newTestPlugin(t, false, 0, "", "")

		pod := testPodSandbox()
		container := testContainer()

		err := p.StartContainer(t.Context(), pod, container)
		require.Error(t, err)
		require.ErrorContains(t, err, "failed to get cgroup ID from container: lookup failed")
		require.ErrorContains(t, err, "Runtime-enforcer has prevented the container 'demo-pod/app' from starting")
		require.Empty(t, p.resolver.PodCacheSnapshot())
	})
}

func TestPluginCreateContainer(t *testing.T) {
	ctx := t.Context()
	pod := testPodSandbox()
	container := testContainer()

	t.Run("returns no adjustment when oci hook paths are unset", func(t *testing.T) {
		p := newTestPlugin(t, false, 0, "", "")
		adj, updates, err := p.CreateContainer(ctx, pod, container)
		require.NoError(t, err)
		require.Nil(t, updates)
		require.Nil(t, adj)
	})

	t.Run("injects createRuntime hook with host binary and socket", func(t *testing.T) {
		p := newTestPlugin(t, false, 0, "/host/oci-hook.sock", "/host/oci-hook")
		adj, updates, err := p.CreateContainer(ctx, pod, container)
		require.NoError(t, err)
		require.Nil(t, updates)
		require.NotNil(t, adj)
		require.NotNil(t, adj.GetHooks())
		rt := adj.GetHooks().GetCreateRuntime()
		require.Len(t, rt, 1)
		require.Equal(t, "/host/oci-hook", rt[0].GetPath())
		require.Equal(t, []string{"/host/oci-hook", "-socket", "/host/oci-hook.sock", "createRuntime"}, rt[0].GetArgs())
	})
}
