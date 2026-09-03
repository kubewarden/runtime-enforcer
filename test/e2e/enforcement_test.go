package e2e_test

import (
	"context"
	"testing"

	"github.com/kubewarden/runtime-enforcer/api/v1alpha1"
	"github.com/kubewarden/runtime-enforcer/internal/types/policymode"
	"github.com/stretchr/testify/require"
	"sigs.k8s.io/e2e-framework/pkg/envconf"
	"sigs.k8s.io/e2e-framework/pkg/features"
	"sigs.k8s.io/e2e-framework/pkg/types"
)

func getEnforcementOnNewPodsTest() types.Feature {
	return features.New("enforcement on new pods").
		Setup(SetupSharedK8sClient).
		Setup(SetupTestNamespace).
		Assess("required resources become available", IfRequiredResourcesAreCreated).
		Assess("a namespace-scoped policy can be enforced correctly",
			func(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
				policy := v1alpha1.WorkloadPolicy{
					Name:      "test-policy",
					Namespace: getNamespace(ctx),
					Spec: v1alpha1.WorkloadPolicySpec{
						Mode: policymode.ProtectString,
						RulesByContainer: map[string]*v1alpha1.WorkloadPolicyRules{
							"opensuse": {
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

				// 1. Create the resource and wait for it to be deployed.
				createAndWaitWP(ctx, t, policy.DeepCopy())
				// 2. Deploy test pods
				createAndWaitOpensuseDeployment(ctx, t, withPolicy("test-policy"))

				// 3. Run command in the pod and verify the result.
				podName, err := findOpensuseDeploymentPod(ctx)
				require.NoError(t, err)

				expectedResults := []struct {
					Commands []string
					Allowed  bool
				}{
					{
						Commands: []string{"/usr/bin/ls"},
						Allowed:  true,
					},
					{
						Commands: []string{"/usr/bin/zypper", "refresh"},
						Allowed:  false,
					},
				}

				for _, expectedResult := range expectedResults {
					t.Log("running:", expectedResult.Commands)

					if expectedResult.Allowed {
						requireExecAllowedInCurrentNamespace(ctx, t, podName, "opensuse", expectedResult.Commands)
					} else {
						requireExecBlockedInCurrentNamespace(ctx, t, podName, "opensuse", expectedResult.Commands)
					}
				}

				// 4. Delete test Deployment
				deleteOpensuseDeployment(ctx, t)

				// 5. Delete WorkloadPolicy and wait for it to be gone.
				deleteAndWaitWP(ctx, t, &policy)
				return ctx
			}).Feature()
}
