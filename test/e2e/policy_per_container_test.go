package e2e_test

import (
	"context"
	"testing"
	"time"

	"github.com/kubewarden/runtime-enforcer/api/v1alpha1"
	"github.com/kubewarden/runtime-enforcer/internal/types/policymode"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/e2e-framework/klient/k8s"
	"sigs.k8s.io/e2e-framework/klient/wait"
	"sigs.k8s.io/e2e-framework/klient/wait/conditions"
	"sigs.k8s.io/e2e-framework/pkg/envconf"
	"sigs.k8s.io/e2e-framework/pkg/features"
	"sigs.k8s.io/e2e-framework/pkg/types"
)

func getPolicyPerContainerTest() types.Feature {
	policyName := "per-container-policy"
	podNameAllowed := "test-pod-allowed-init-main"
	podNameBlocked := "test-pod-blocked-init-main"

	return features.New("policy per container").
		Setup(SetupSharedK8sClient).
		Setup(SetupTestNamespace).
		Setup(func(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
			policy := v1alpha1.WorkloadPolicy{
				Name:      policyName,
				Namespace: getNamespace(ctx),
				Spec: v1alpha1.WorkloadPolicySpec{
					Mode: policymode.ProtectString,
					RulesByContainer: map[string]*v1alpha1.WorkloadPolicyRules{
						"init-container": {
							Executables: v1alpha1.WorkloadPolicyExecutables{
								Allowed: []string{
									"/usr/bin/echo",
								},
							},
						},
						"main-container": {
							Executables: v1alpha1.WorkloadPolicyExecutables{
								Allowed: []string{
									"/usr/bin/ls",
									"/usr/bin/sleep",
								},
							},
						},
					},
				},
			}
			createAndWaitWP(ctx, t, policy.DeepCopy())
			return ctx
		}).
		Assess("required resources become available", IfRequiredResourcesAreCreated).
		Assess("pod starts when init container runs allowed command",
			func(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
				t.Log("creating pod where init container runs allowed command (echo)")

				r := getClient(ctx)

				pod := corev1.Pod{
					Name:      podNameAllowed,
					Namespace: getNamespace(ctx),
					Labels: map[string]string{
						v1alpha1.PolicyLabelKey: policyName,
					},
					Spec: corev1.PodSpec{
						InitContainers: []corev1.Container{
							{
								Name:    "init-container",
								Image:   "registry.opensuse.org/opensuse/bci/bci-ci:3",
								Command: []string{"echo", "init completed"},
							},
						},
						Containers: []corev1.Container{
							{
								Name:    "main-container",
								Image:   "registry.opensuse.org/opensuse/bci/bci-ci:3",
								Command: []string{"sleep", "3600"},
							},
						},
						RestartPolicy: corev1.RestartPolicyNever,
					},
				}

				err := r.Create(ctx, &pod)
				require.NoError(t, err, "failed to create pod")

				err = wait.For(
					conditions.New(r).PodReady(&pod),
					wait.WithTimeout(defaultOperationTimeout),
				)
				require.NoError(t, err, "pod did not become ready")

				err = r.Get(ctx, podNameAllowed, getNamespace(ctx), &pod)
				require.NoError(t, err, "failed to get pod")

				// Verify init container completed successfully (echo is allowed)
				require.NotEmpty(t, pod.Status.InitContainerStatuses, "init container status should exist")
				initStatus := pod.Status.InitContainerStatuses[0]
				require.NotNil(t, initStatus.State.Terminated, "init container should have terminated")
				require.Equal(
					t,
					int32(0),
					initStatus.State.Terminated.ExitCode,
					"init container should exit successfully",
				)

				require.NotEmpty(t, pod.Status.ContainerStatuses, "main container status should exist")
				mainStatus := pod.Status.ContainerStatuses[0]
				require.NotNil(t, mainStatus.State.Running, "main container should be running")

				return ctx
			}).
		Assess("pod fails when init container runs blocked command",
			func(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
				t.Log("creating pod where init container runs blocked command (date)")

				r := getClient(ctx)

				blockedPod := corev1.Pod{
					Name:      podNameBlocked,
					Namespace: getNamespace(ctx),
					Labels: map[string]string{
						v1alpha1.PolicyLabelKey: policyName,
					},
					Spec: corev1.PodSpec{
						InitContainers: []corev1.Container{
							{
								Name:    "init-container",
								Image:   "registry.opensuse.org/opensuse/bci/bci-ci:3",
								Command: []string{"date"},
							},
						},
						Containers: []corev1.Container{
							{
								Name:    "main-container",
								Image:   "registry.opensuse.org/opensuse/bci/bci-ci:3",
								Command: []string{"sleep", "3600"},
							},
						},
						RestartPolicy: corev1.RestartPolicyNever,
					},
				}

				err := r.Create(ctx, &blockedPod)
				require.NoError(t, err, "failed to create pod with blocked init command")

				// Retry until the pod init container status is updated
				// init container should fail (date is not allowed)
				err = wait.For(conditions.New(r).ResourceMatch(&blockedPod, func(obj k8s.Object) bool {
					pod, ok := obj.(*corev1.Pod)
					if !ok {
						return false
					}
					t.Log("checking pod init container status:", pod.Status.InitContainerStatuses)
					// we don't have status for init containers yet
					if len(pod.Status.InitContainerStatuses) == 0 {
						t.Log("empty init container status")
						return false
					}
					initStatus := pod.Status.InitContainerStatuses[0]
					if initStatus.State.Terminated == nil {
						t.Log("terminated state not set")
						return false
					}
					if initStatus.State.Terminated.ExitCode == 0 {
						t.Log("exit code == 0")
						return false
					}
					return true
				}), wait.WithTimeout(15*time.Second))
				require.NoError(t, err, "init container should fail because date is not allowed")

				err = r.Delete(ctx, &blockedPod)
				require.NoError(t, err, "failed to delete blocked pod")

				return ctx
			}).
		Assess("ls is allowed in main container",
			func(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
				t.Log("verifying ls is allowed in main container")

				_, _ = requireExecAllowedInCurrentNamespace(
					ctx,
					t,
					podNameAllowed,
					"main-container",
					[]string{"ls", "/"},
				)

				return ctx
			}).
		Assess("bash is blocked in main container",
			func(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
				t.Log("verifying bash is blocked in main container")

				requireExecBlockedInCurrentNamespace(
					ctx,
					t,
					podNameAllowed,
					"main-container",
					[]string{"bash", "-c", "echo 'bash should be blocked'"},
				)

				return ctx
			}).
		Teardown(func(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
			t.Log("cleaning up test resources")

			r := getClient(ctx)

			pod := corev1.Pod{
				Name:      podNameAllowed,
				Namespace: getNamespace(ctx),
			}
			err := r.Delete(ctx, &pod)
			require.NoError(t, err, "failed to delete pod")

			err = wait.For(
				conditions.New(r).ResourceDeleted(&pod),
				wait.WithTimeout(defaultOperationTimeout),
			)
			require.NoError(t, err, "pod was not deleted within timeout")

			policy := v1alpha1.WorkloadPolicy{
				Name:      policyName,
				Namespace: getNamespace(ctx),
			}
			deleteAndWaitWP(ctx, t, &policy)

			return ctx
		}).Feature()
}
