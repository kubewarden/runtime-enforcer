package e2e_test

import (
	"context"
	"testing"

	"github.com/kubewarden/runtime-enforcer/api/v1alpha1"
	"github.com/kubewarden/runtime-enforcer/internal/types/policymode"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/e2e-framework/klient/wait"
	"sigs.k8s.io/e2e-framework/klient/wait/conditions"
	"sigs.k8s.io/e2e-framework/pkg/envconf"
	"sigs.k8s.io/e2e-framework/pkg/features"
	"sigs.k8s.io/e2e-framework/pkg/types"
)

const (
	podName          = "test-pod"
	policyName       = "test-policy"
	mainContainer    = "main"
	sidecarContainer = "sidecar"
)

func getPolicyUpdateTest() types.Feature {
	return features.New("policy-update").
		Setup(SetupSharedK8sClient).
		Setup(SetupTestNamespace).
		Setup(func(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
			policy := v1alpha1.WorkloadPolicy{
				Name:      policyName,
				Namespace: getNamespace(ctx),
				Spec: v1alpha1.WorkloadPolicySpec{
					Mode: policymode.ProtectString,
					RulesByContainer: map[string]*v1alpha1.WorkloadPolicyRules{
						mainContainer: {
							Executables: v1alpha1.WorkloadPolicyExecutables{
								Allowed: []string{
									"/usr/bin/ls",
									"/usr/bin/bash",
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
		Setup(func(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
			t.Log("creating pod with two containers (main, sidecar)")

			r := getClient(ctx)
			namespace := getNamespace(ctx)

			pod := corev1.Pod{
				Name:      podName,
				Namespace: namespace,
				Labels: map[string]string{
					v1alpha1.PolicyLabelKey: policyName,
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:    mainContainer,
							Image:   "registry.opensuse.org/opensuse/bci/bci-ci:3",
							Command: []string{"sleep", "3600"},
						},
						{
							Name:    sidecarContainer,
							Image:   "registry.opensuse.org/opensuse/bci/bci-ci:3",
							Command: []string{"sleep", "3600"},
						},
					},
					RestartPolicy: corev1.RestartPolicyNever,
				},
			}

			err := r.Create(ctx, &pod)
			require.NoError(t, err, "failed to create policy-update pod")
			err = wait.For(conditions.New(r).PodReady(&pod), wait.WithTimeout(defaultOperationTimeout))
			require.NoError(t, err, "pod did not become ready")

			return ctx
		}).
		Assess("required resources become available", IfRequiredResourcesAreCreated).
		Assess("policy update with new executables is enforced correctly",
			func(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
				r := getClient(ctx)
				namespace := getNamespace(ctx)

				t.Log("verifying /usr/bin/cat is blocked in main before update")
				requireExecBlockedInCurrentNamespace(
					ctx,
					t,
					podName,
					mainContainer,
					[]string{"/usr/bin/cat", "/etc/hostname"},
				)

				t.Log("updating policy to add /usr/bin/cat")

				var updatedPolicy v1alpha1.WorkloadPolicy
				err := r.Get(ctx, policyName, namespace, &updatedPolicy)
				require.NoError(t, err, "failed to get policy for update")

				updatedPolicy.Spec.RulesByContainer[mainContainer].Executables.Allowed = []string{
					"/usr/bin/ls",
					"/usr/bin/bash",
					"/usr/bin/sleep",
					"/usr/bin/cat",
				}

				err = r.Update(ctx, &updatedPolicy)
				require.NoError(t, err, "failed to update policy")

				// This is almost useless because the policy won't change status during the update.
				waitForWorkloadPolicyStatusToBeUpdated(ctx, t, updatedPolicy.DeepCopy())

				t.Log("verifying /usr/bin/cat is allowed in main after update")
				stdout, _ := requireExecAllowedInCurrentNamespace(
					ctx,
					t,
					podName,
					mainContainer,
					[]string{"/usr/bin/cat", "/etc/hostname"},
				)
				require.NotEmpty(t, stdout, "cat should have produced output")

				t.Log("verifying /usr/bin/zypper is still blocked in main")
				requireExecBlockedInCurrentNamespace(
					ctx,
					t,
					podName,
					mainContainer,
					[]string{"/usr/bin/zypper", "refresh"},
				)

				return ctx
			}).
		Assess("policy update can add enforcement for a new container",
			func(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
				r := getClient(ctx)
				namespace := getNamespace(ctx)

				// 1. Verify that /usr/bin/mkdir is blocked in main but allowed in sidecar
				t.Log("verifying /usr/bin/mkdir is blocked in main and allowed in sidecar before update")

				requireExecBlockedInCurrentNamespace(
					ctx,
					t,
					podName,
					mainContainer,
					[]string{"/usr/bin/mkdir", "/tmp/main-dir-add"},
				)

				_, _ = requireExecAllowedInCurrentNamespace(
					ctx,
					t,
					podName,
					sidecarContainer,
					[]string{"/usr/bin/mkdir", "/tmp/sidecar-dir-add"},
				)

				// 2. Update the policy to add the sidecar container to RulesByContainer
				t.Log("updating policy to add sidecar container rules")

				var updatedPolicy v1alpha1.WorkloadPolicy
				err := r.Get(ctx, policyName, namespace, &updatedPolicy)
				require.NoError(t, err, "failed to get policy for add-container update")

				updatedPolicy.Spec.RulesByContainer[sidecarContainer] = &v1alpha1.WorkloadPolicyRules{
					Executables: v1alpha1.WorkloadPolicyExecutables{
						Allowed: []string{
							"/usr/bin/ls",
							"/usr/bin/bash",
							"/usr/bin/sleep",
						},
					},
				}

				err = r.Update(ctx, &updatedPolicy)
				require.NoError(t, err, "failed to update policy to add sidecar rules")

				waitForWorkloadPolicyStatusToBeUpdated(ctx, t, updatedPolicy.DeepCopy())

				// 3. Verify both main and sidecar are now protected (mkdir blocked in both)
				t.Log("verifying both main and sidecar are protected after update")

				requireExecBlockedInCurrentNamespace(
					ctx,
					t,
					podName,
					mainContainer,
					[]string{"/usr/bin/mkdir", "/tmp/main-dir-add-2"},
				)

				requireExecBlockedInCurrentNamespace(
					ctx,
					t,
					podName,
					sidecarContainer,
					[]string{"/usr/bin/mkdir", "/tmp/sidecar-dir-add-2"},
				)

				return ctx
			}).
		Assess("policy update can disable enforcement for a single container",
			func(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
				r := getClient(ctx)
				namespace := getNamespace(ctx)

				t.Log("policy already has main and sidecar from previous assessment")
				var wp v1alpha1.WorkloadPolicy
				err := r.Get(ctx, policyName, namespace, &wp)
				require.NoError(t, err, "failed to get policy")

				// 1. Update the policy to remove the sidecar container from RulesByContainer
				t.Log("updating policy to remove sidecar container rules")
				delete(wp.Spec.RulesByContainer, sidecarContainer)

				err = r.Update(ctx, &wp)
				require.NoError(t, err, "failed to update policy to remove sidecar rules")
				waitForWorkloadPolicyStatusToBeUpdated(ctx, t, wp.DeepCopy())

				// 2. Verify main is still protected (mkdir blocked) while sidecar is now unprotected (mkdir allowed)
				t.Log("verifying main container remains protected and sidecar is unprotected after update")

				requireExecBlockedInCurrentNamespace(
					ctx,
					t,
					podName,
					mainContainer,
					[]string{"/usr/bin/mkdir", "/tmp/main-dir-2"},
				)

				_, _ = requireExecAllowedInCurrentNamespace(
					ctx,
					t,
					podName,
					sidecarContainer,
					[]string{"/usr/bin/mkdir", "/tmp/sidecar-dir-2-%d"},
				)

				t.Log("cleaning up pod")
				pod := corev1.Pod{
					Name:      podName,
					Namespace: namespace,
				}
				err = r.Delete(ctx, &pod)
				require.NoError(t, err, "failed to delete pod")
				err = wait.For(
					conditions.New(r).ResourceDeleted(&pod),
					wait.WithTimeout(defaultOperationTimeout),
				)
				require.NoError(t, err, "pod %q was not deleted within timeout", podName)

				t.Log("cleaning up policy")
				err = r.Delete(ctx, &wp)
				require.NoError(t, err, "failed to delete policy")
				return ctx
			}).
		Teardown(func(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
			t.Log("uninstalling test resources")
			_ = getClient(ctx).Delete(ctx, &corev1.Namespace{Name: getNamespace(ctx)})
			return ctx
		}).Feature()
}
