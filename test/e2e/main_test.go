package e2e_test

import (
	"context"
	"testing"
	"time"

	"github.com/kubewarden/runtime-enforcer/api/v1alpha1"
	"github.com/kubewarden/runtime-enforcer/internal/types/policymode"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/e2e-framework/klient/k8s"
	"sigs.k8s.io/e2e-framework/klient/wait"
	"sigs.k8s.io/e2e-framework/klient/wait/conditions"
	"sigs.k8s.io/e2e-framework/pkg/envconf"
	"sigs.k8s.io/e2e-framework/pkg/features"
	"sigs.k8s.io/e2e-framework/pkg/types"
)

func getMainTest() types.Feature {
	return features.New("Main").
		Setup(SetupSharedK8sClient).
		Setup(SetupTestNamespace).
		Setup(func(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
			createAndWaitOpensuseDeployment(ctx, t)
			return ctx
		}).
		Assess("required resources become available", IfRequiredResourcesAreCreated).
		Assess("the workload policy proposal is created successfully for the opensuse pod",
			func(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
				r := getClient(ctx)

				proposal := v1alpha1.WorkloadPolicyProposal{
					Name:      "deploy-opensuse-deployment",
					Namespace: getNamespace(ctx),
				}
				err := wait.For(conditions.New(r).ResourceMatch(
					&proposal,
					func(object k8s.Object) bool {
						obj := object.(*v1alpha1.WorkloadPolicyProposal)
						if obj.OwnerReferences[0].Name == opensuseDeploymentName &&
							obj.OwnerReferences[0].Kind == "Deployment" {
							return true
						}
						return false
					}),
					wait.WithTimeout(defaultOperationTimeout),
				)
				require.NoError(t, err)

				return context.WithValue(ctx, key("group"), proposal.Name)
			}).
		Assess("the running process is learned",
			func(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
				id := ctx.Value(key("group")).(string)
				r := getClient(ctx)

				t.Log("waiting for workload policy proposal to be created: ", id)

				proposal := v1alpha1.WorkloadPolicyProposal{
					Name:      id,
					Namespace: getNamespace(ctx),
				}

				// There are two categories of processes to be learned:
				// 1. /usr/bin/bash: the container entrypoint.
				// 2. /usr/bin/sleep & /usr/bin/ls: the commands the container executes
				t.Log("waiting for processes to be learned")

				err := wait.For(conditions.New(r).ResourceMatch(
					&proposal,
					func(_ k8s.Object) bool {
						rules := proposal.Spec.RulesByContainer["opensuse"]

						return verifyOpensuseLearnedProcesses(rules.Executables.Allowed)
					}),
					wait.WithTimeout(defaultOperationTimeout),
				)
				require.NoError(t, err)

				return context.WithValue(ctx, key("proposal"), &proposal)
			}).
		Assess("a proposal is promoted to a workload policy and the WP is created",
			func(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
				proposal := ctx.Value(key("proposal")).(*v1alpha1.WorkloadPolicyProposal)
				policy := v1alpha1.WorkloadPolicy{
					Name:      "test-policy",
					Namespace: proposal.ObjectMeta.Namespace,
					Spec: v1alpha1.WorkloadPolicySpec{
						Mode: policymode.ProtectString,
						RulesByContainer: map[string]*v1alpha1.WorkloadPolicyRules{
							"opensuse": {
								Executables: v1alpha1.WorkloadPolicyExecutables{
									Allowed: proposal.Spec.RulesByContainer["opensuse"].Executables.Allowed,
								},
							},
						},
					},
				}
				createAndWaitWP(ctx, t, policy.DeepCopy())
				return context.WithValue(ctx, key("policy"), &policy)
			}).
		Assess("update the workload to apply policy",
			func(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
				// Delete the opensuse deployment
				deleteOpensuseDeployment(ctx, t)

				// Create the opensuse deployment again with policy label assigned.
				createAndWaitOpensuseDeployment(ctx, t, withPolicy("test-policy"))
				return ctx
			}).
		Assess("pod exec will be blocked",
			func(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
				podName, err := findOpensuseDeploymentPod(ctx)
				require.NoError(t, err)
				requireExecBlockedInCurrentNamespace(ctx, t, podName, "opensuse", []string{"mkdir"})
				return ctx
			}).
		Assess("Verify a non-referenced WorkloadPolicy can be deleted",
			func(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
				var err error
				r := getClient(ctx)
				nonReferencedPolicyName := "non-referenced-wp"

				// Create a new WorkloadPolicy
				nonReferencedPolicy := v1alpha1.WorkloadPolicy{
					Name:      nonReferencedPolicyName,
					Namespace: getNamespace(ctx),
					Spec: v1alpha1.WorkloadPolicySpec{
						Mode: policymode.MonitorString,
						RulesByContainer: map[string]*v1alpha1.WorkloadPolicyRules{
							"opensuse": {
								Executables: v1alpha1.WorkloadPolicyExecutables{
									Allowed: []string{"/bin/true"},
								},
							},
						},
					},
				}
				require.NoError(
					t,
					r.Create(ctx, &nonReferencedPolicy),
					"failed to create non-referenced WorkloadPolicy",
				)

				err = r.Delete(ctx, &nonReferencedPolicy)
				require.NoError(t, err, "failed to delete non-referenced WorkloadPolicy")

				// Wait for the WorkloadPolicy to be deleted
				err = wait.For(
					conditions.New(r).ResourceDeleted(&nonReferencedPolicy),
					wait.WithTimeout(time.Minute*2),
					wait.WithInterval(time.Second*5),
				)
				require.NoError(
					t,
					err,
					"policy was not deleted within timeout",
				)

				return ctx
			}).
		Assess("Verify a referenced WorkloadPolicy cannot be deleted",
			func(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
				var err error
				r := getClient(ctx)
				referencedPolicyName := "referenced-wp"
				podName := "referenced-wp-pod"

				// Create a new WorkloadPolicy
				referencedPolicy := v1alpha1.WorkloadPolicy{
					Name:      referencedPolicyName,
					Namespace: getNamespace(ctx),
					Spec: v1alpha1.WorkloadPolicySpec{
						Mode: policymode.MonitorString,
						RulesByContainer: map[string]*v1alpha1.WorkloadPolicyRules{
							"opensuse": {
								Executables: v1alpha1.WorkloadPolicyExecutables{
									Allowed: []string{"/bin/true"},
								},
							},
						},
					},
				}
				require.NoError(
					t,
					r.Create(ctx, &referencedPolicy),
					"failed to create referenced WorkloadPolicy",
				)

				pod := corev1.Pod{
					Name:      podName,
					Namespace: getNamespace(ctx),
					Labels: map[string]string{
						v1alpha1.PolicyLabelKey: referencedPolicyName,
					},
					Spec: corev1.PodSpec{
						Containers: []corev1.Container{
							{
								Name:  "pause",
								Image: "registry.k8s.io/pause",
							},
						},
					},
				}
				require.NoError(
					t,
					r.Create(ctx, &pod),
					"failed to create Pod",
				)

				// The validating webhook must reject the delete while a pod references the policy.
				err = r.Delete(ctx, &referencedPolicy)
				require.Error(t, err, "expected delete to be denied while a Pod references the policy")
				require.True(t, apierrors.IsForbidden(err),
					"expected 403 Forbidden from validating webhook, got: %v", err)

				// Verify the policy still exists
				err = r.Get(ctx, referencedPolicy.Name, getNamespace(ctx), &referencedPolicy)
				require.NoError(t, err, "WorkloadPolicy should still exist after denied delete")
				require.Nil(t, referencedPolicy.DeletionTimestamp,
					"WorkloadPolicy must not be terminating after a denied delete")

				// Remove the pod
				require.NoError(
					t,
					r.Delete(ctx, &pod),
					"failed to delete Pod",
				)

				// Wait for the pod to be deleted
				err = wait.For(
					conditions.New(r).ResourceDeleted(&pod),
					wait.WithTimeout(2*time.Minute),
					wait.WithInterval(5*time.Second),
				)
				require.NoError(
					t,
					err,
					"Pod was not deleted within timeout",
				)

				// Now the policy can be deleted.
				require.NoError(t, r.Delete(ctx, &referencedPolicy),
					"failed to delete WorkloadPolicy after Pod was removed")

				err = wait.For(
					conditions.New(r).ResourceDeleted(&referencedPolicy),
					wait.WithTimeout(2*time.Minute),
					wait.WithInterval(5*time.Second),
				)
				require.NoError(
					t,
					err,
					"WorkloadPolicy should be deleted after Pod is removed",
				)

				return ctx
			}).
		Teardown(func(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
			deleteOpensuseDeployment(ctx, t)
			return ctx
		}).Feature()
}
