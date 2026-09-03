package e2e_test

import (
	"context"
	"testing"

	"github.com/kubewarden/runtime-enforcer/api/v1alpha1"
	"github.com/kubewarden/runtime-enforcer/internal/types/policymode"
	"github.com/stretchr/testify/require"
	"sigs.k8s.io/e2e-framework/klient/k8s"
	"sigs.k8s.io/e2e-framework/klient/wait"
	"sigs.k8s.io/e2e-framework/klient/wait/conditions"
	"sigs.k8s.io/e2e-framework/pkg/envconf"
	"sigs.k8s.io/e2e-framework/pkg/features"
	"sigs.k8s.io/e2e-framework/pkg/types"
)

func getPromotionTest() types.Feature {
	return features.New("Promotion").
		Setup(SetupSharedK8sClient).
		Setup(SetupTestNamespace).
		Setup(func(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
			createAndWaitOpensuseDeployment(ctx, t)
			return ctx
		}).
		Assess("required resources become available", IfRequiredResourcesAreCreated).
		Assess("the workload proposal is created successfully for the opensuse pod",
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
						if len(obj.OwnerReferences) == 0 {
							return false
						}
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

				t.Log("waiting for policy proposal to be created: ", id)

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
						rules, ok := proposal.Spec.RulesByContainer["opensuse"]

						if !ok {
							return false
						}

						return verifyOpensuseLearnedProcesses(rules.Executables.Allowed)
					}),
					wait.WithTimeout(defaultOperationTimeout),
				)
				require.NoError(t, err)

				return context.WithValue(ctx, key("proposal"), &proposal)
			}).
		Assess("a proposal is promoted to a policy through labeling and the workloadPolicy is created",
			func(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
				t.Log("create a policy")

				r := getClient(ctx)
				proposal := ctx.Value(key("proposal")).(*v1alpha1.WorkloadPolicyProposal)

				t.Log("promote the policy proposal: ", proposal.Name)

				proposal.SetPromotionLabel(policymode.MonitorString)
				err := r.Update(ctx, proposal)
				require.NoError(t, err)

				t.Log("waiting for the policy to be created: ", proposal.Name)

				policy := v1alpha1.WorkloadPolicy{
					Name:      proposal.ObjectMeta.Name,
					Namespace: proposal.ObjectMeta.Namespace,
					Spec: v1alpha1.WorkloadPolicySpec{
						Mode: policymode.MonitorString,
						RulesByContainer: map[string]*v1alpha1.WorkloadPolicyRules{
							"opensuse": {
								Executables: v1alpha1.WorkloadPolicyExecutables{
									Allowed: proposal.Spec.RulesByContainer["opensuse"].Executables.Allowed,
								},
							},
						},
					},
				}

				err = wait.For(conditions.New(r).ResourceMatch(&policy, func(_ k8s.Object) bool {
					return true
				}), wait.WithTimeout(defaultOperationTimeout))
				require.NoError(t, err)

				t.Log("waiting for the WorkloadPolicyProposal to be deleted: ", proposal.Name)
				err = wait.For(
					conditions.New(r).ResourceDeleted(proposal),
					wait.WithTimeout(defaultOperationTimeout),
				)
				require.NoError(t, err)

				return context.WithValue(ctx, key("policy"), &policy)
			}).
		Assess("pod exec will not be blocked since the policy is in monitoring mode",
			func(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
				podName, err := findOpensuseDeploymentPod(ctx)
				require.NoError(t, err)
				// /usr/bin/true is not allowed but we are in monitor mode.
				_, _ = requireExecAllowedInCurrentNamespace(ctx, t, podName, "opensuse", []string{"/usr/bin/true"})
				return ctx
			}).
		Assess("delete policy", func(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
			r := getClient(ctx)
			policy := ctx.Value(key("policy")).(*v1alpha1.WorkloadPolicy)

			err := r.Delete(ctx, policy)
			require.NoError(t, err)

			return ctx
		}).
		Teardown(func(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
			deleteOpensuseDeployment(ctx, t)
			return ctx
		}).Feature()
}
