package e2e_test

import (
	"context"
	"testing"

	"github.com/kubewarden/runtime-enforcer/api/v1alpha1"
	"github.com/kubewarden/runtime-enforcer/internal/types/policymode"
	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	"sigs.k8s.io/e2e-framework/klient/decoder"
	"sigs.k8s.io/e2e-framework/klient/k8s"
	"sigs.k8s.io/e2e-framework/klient/wait"
	"sigs.k8s.io/e2e-framework/pkg/envconf"
	"sigs.k8s.io/e2e-framework/pkg/features"
	"sigs.k8s.io/e2e-framework/pkg/types"
)

// This test verifies the protection is persistent during rolling update of agent.
func getRollingUpdateTest() types.Feature {
	return features.New("Rolling update").
		Setup(SetupSharedK8sClient).
		Setup(SetupTestNamespace).
		Setup(func(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
			policy := &v1alpha1.WorkloadPolicy{
				Name:      "test-policy",
				Namespace: getNamespace(ctx),
				Spec: v1alpha1.WorkloadPolicySpec{
					Mode: policymode.ProtectString,
					RulesByContainer: map[string]*v1alpha1.WorkloadPolicyRules{
						"opensuse": {
							Executables: v1alpha1.WorkloadPolicyExecutables{
								Allowed: []string{
									"/usr/bin/bash",
									"/usr/bin/ls",
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
		Setup(func(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
			createAndWaitOpensuseDeployment(ctx, t, withPolicy("test-policy"),
				decoder.MutateOption(func(obj k8s.Object) error {
					deployment := obj.(*appsv1.Deployment)
					// This will cause a lot of violations so it is possible to see some `violation buffer full` logs.
					deployment.Spec.Template.Spec.Containers[0].Command = []string{
						"bash",
						"-c",
						"while true; do mkdir /tmp/testdir;done", // this command is supposed to be failing throughout rolling update.
					}
					return nil
				}))
			return ctx
		}).
		Assess("verify that the test directory doesn't exist and mkdir will be blocked",
			func(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
				podName, err := findOpensuseDeploymentPod(ctx)
				require.NoError(t, err)

				// Run mkdir to verify that it is blocked.
				requireExecBlockedInCurrentNamespace(ctx, t, podName, "opensuse", []string{"mkdir"})

				// Verify that the test directory doesn't exist.
				_, _ = requireExecAllowedInCurrentNamespace(
					ctx,
					t,
					podName,
					"opensuse",
					[]string{"bash", "-c", "[ ! -d /tmp/testdir ]"},
				)
				return ctx
			}).
		Assess("rolling update should succeed", func(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
			r := getClient(ctx)
			agentDaemonSet := appsv1.DaemonSet{}
			err := r.Get(
				ctx,
				"runtime-enforcer-agent",
				runtimeEnforcerNamespace,
				&agentDaemonSet,
			)
			require.NoError(t, err)
			agentDaemonSet.Spec.Template.Labels["restart"] = "restart" // trigger rolling update

			err = r.Update(ctx, &agentDaemonSet)
			require.NoError(t, err)

			err = wait.For(daemonSetUpToDate(r, &appsv1.DaemonSet{
				Name:      "runtime-enforcer-agent",
				Namespace: runtimeEnforcerNamespace,
			}),
				wait.WithTimeout(defaultOperationTimeout),
			)
			require.NoError(t, err)
			return ctx
		}).
		Assess("/tmp/testdir should never be created", func(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
			podName, err := findOpensuseDeploymentPod(ctx)
			require.NoError(t, err)

			_, _ = requireExecAllowedInCurrentNamespace(
				ctx,
				t,
				podName,
				"opensuse",
				[]string{"bash", "-c", "[ ! -d /tmp/testdir ]"},
			)
			return ctx
		}).
		Teardown(func(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
			deleteOpensuseDeployment(ctx, t)
			return ctx
		}).Feature()
}
