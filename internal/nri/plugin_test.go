package nri

import (
	"errors"
	"testing"

	"github.com/containerd/nri/pkg/api"
	"github.com/stretchr/testify/require"

	"github.com/kubewarden/runtime-enforcer/api/v1alpha1"
	"github.com/kubewarden/runtime-enforcer/internal/resolver"
	"github.com/kubewarden/runtime-enforcer/internal/testutil"
	"github.com/kubewarden/runtime-enforcer/internal/types/workloadkind"
)

func newTestPlugin(
	t *testing.T,
	failOpen bool,
	policyFailOpen bool,
	cgroupToReturn resolver.CgroupID,
) *plugin {
	t.Helper()

	return &plugin{
		logger:         testutil.NewTestLogger(t),
		resolver:       resolver.NewTestResolver(t),
		failOpen:       failOpen,
		policyFailOpen: policyFailOpen,
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

func testPodSandboxWithMissingPolicy() *api.PodSandbox {
	pod := testPodSandbox()
	pod.Labels[v1alpha1.PolicyLabelKey] = "missing"
	return pod
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

		p := newTestPlugin(t, false, false, 100)

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
		p := newTestPlugin(t, true, false, 0)
		pod := testPodSandbox()
		container := testContainer()

		err := p.StartContainer(t.Context(), pod, container)
		require.NoError(t, err)
		require.Empty(t, p.resolver.PodCacheSnapshot())
	})

	t.Run("returns wrapped error in fail-closed mode when cgroup lookup fails", func(t *testing.T) {
		p := newTestPlugin(t, false, false, 0)

		pod := testPodSandbox()
		container := testContainer()

		err := p.StartContainer(t.Context(), pod, container)
		require.Error(t, err)
		require.ErrorContains(t, err, "runtime-enforcer has prevented the container 'demo-pod/app' from starting")
		require.Empty(t, p.resolver.PodCacheSnapshot())
	})
	t.Run("handles a missing policy according to the fail-open settings", func(t *testing.T) {
		cases := []struct {
			name           string
			policyFailOpen bool
			nriFailOpen    bool
			wantErr        string
		}{
			{
				name:    "blocks the container when both settings are false",
				wantErr: "agent.policyFailopen=true",
			},
			{
				name:           "starts the container when policyFailOpen is true",
				policyFailOpen: true,
			},
			{
				name:        "starts the container when nriFailOpen is true",
				nriFailOpen: true,
			},
			{
				name:           "starts the container when both settings are true",
				policyFailOpen: true,
				nriFailOpen:    true,
			},
		}
		for _, c := range cases {
			t.Run(c.name, func(t *testing.T) {
				p := newTestPlugin(t, c.nriFailOpen, c.policyFailOpen, 100)
				pod := testPodSandboxWithMissingPolicy()

				err := p.StartContainer(t.Context(), pod, testContainer())
				if c.wantErr != "" {
					require.ErrorContains(t, err, c.wantErr)
					require.ErrorContains(t, err, "WorkloadPolicy 'missing' does not exist")
				} else {
					require.NoError(t, err)
				}
				require.Contains(t, p.resolver.PodCacheSnapshot(), pod.GetUid())
			})
		}
	})
}

func TestPluginSynchronize(t *testing.T) {
	p := newTestPlugin(t, false, false, 100)
	pod := testPodSandboxWithMissingPolicy()
	container := testContainer()
	container.PodSandboxId = pod.GetId()

	updates, err := p.Synchronize(t.Context(), []*api.PodSandbox{pod}, []*api.Container{container})
	require.NoError(t, err)
	require.Empty(t, updates)
	require.True(t, p.resolver.IsNRISynchronized())
	require.Contains(t, p.resolver.PodCacheSnapshot(), pod.GetUid())
}
