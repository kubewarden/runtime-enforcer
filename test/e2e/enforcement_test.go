package e2e_test

import (
	"bytes"
	"context"
	"strings"
	"testing"

	tragonv1alpha1 "github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/neuvector/runtime-enforcement/api/v1alpha1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/e2e-framework/klient/decoder"
	"sigs.k8s.io/e2e-framework/klient/k8s"
	"sigs.k8s.io/e2e-framework/klient/k8s/resources"
	"sigs.k8s.io/e2e-framework/klient/wait"
	"sigs.k8s.io/e2e-framework/klient/wait/conditions"
	"sigs.k8s.io/e2e-framework/pkg/envconf"
	"sigs.k8s.io/e2e-framework/pkg/features"
	"sigs.k8s.io/e2e-framework/pkg/types"
)

func getEnforcementTest() types.Feature {
	return features.New("Enforcement").
		Setup(SetupSharedK8sClient).
		Setup(func(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
			t.Log("installing test Ubuntu deployment")

			r := ctx.Value(key("client")).(*resources.Resources)

			err := decoder.ApplyWithManifestDir(
				ctx,
				r,
				"./testdata",
				"ubuntu-deployment.yaml",
				[]resources.CreateOption{},
				decoder.MutateNamespace(workloadNamespace),
			)
			assert.NoError(t, err, "failed to apply test data")

			return ctx
		}).
		Assess("required resources become available", IfRequiredResourcesAreCreated).
		Assess("a namespace-scoped policy can be enforced correctly",
			func(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
				t.Log("create a security policy")

				r := ctx.Value(key("client")).(*resources.Resources)

				testcases := []struct {
					AllowedExecutables v1alpha1.WorkloadSecurityPolicyExecutables
					expectedResults    []struct {
						Commands []string
						Allowed  bool
					}
				}{
					{
						AllowedExecutables: v1alpha1.WorkloadSecurityPolicyExecutables{
							Allowed: []string{
								"/usr/bin/ls",
								"/usr/bin/bash",
								"/usr/bin/sleep",
							},
							AllowedPrefixes: []string{},
						},
						expectedResults: []struct {
							Commands []string
							Allowed  bool
						}{
							{
								Commands: []string{"/usr/bin/ls"},
								Allowed:  true,
							},
							{
								Commands: []string{"/usr/bin/apt", "update"},
								Allowed:  false,
							},
						},
					},
					{
						AllowedExecutables: v1alpha1.WorkloadSecurityPolicyExecutables{
							Allowed: []string{},
							AllowedPrefixes: []string{
								"/usr/bin/",
							},
						},
						expectedResults: []struct {
							Commands []string
							Allowed  bool
						}{
							{
								Commands: []string{"/usr/bin/ls"},
								Allowed:  true,
							},
							{
								Commands: []string{"/usr/bin/bash", "-c", "echo hello"},
								Allowed:  true,
							},
						},
					},
				}

				for _, tc := range testcases {
					policy := v1alpha1.WorkloadSecurityPolicy{
						ObjectMeta: metav1.ObjectMeta{
							Name:      "test-policy",
							Namespace: workloadNamespace,
						},
						Spec: v1alpha1.WorkloadSecurityPolicySpec{
							Mode: "protect",
							Rules: v1alpha1.WorkloadSecurityPolicyRules{
								Executables: tc.AllowedExecutables,
							},
							Severity: 9,
							Message:  "test-policy",
							Tags:     []string{"test-policy"},
						},
					}

					// 1. Create the resource and wait for Tetragon policy to be created.
					err := r.Create(ctx, &policy)
					require.NoError(t, err, "create policy")

					tp := tragonv1alpha1.TracingPolicyNamespaced{
						ObjectMeta: metav1.ObjectMeta{
							Name:      policy.Name,
							Namespace: policy.Namespace,
						},
					}

					err = wait.For(conditions.New(r).ResourceMatch(&tp, func(_ k8s.Object) bool {
						return true
					}), wait.WithTimeout(DefaultTimeout))
					require.NoError(t, err)

					assert.Len(t, "1", len(tp.Spec.KProbes))
					assert.Equal(t, []string{"test-policy"}, tp.Spec.KProbes[0].Tags)
					assert.Equal(t, "[9] test-policy", tp.Spec.KProbes[0].Message)

					// 2. Run command in the pod and verify the result.
					var podName string
					var pods corev1.PodList
					err = r.WithNamespace(workloadNamespace).List(ctx, &pods)
					require.NoError(t, err)

					for _, v := range pods.Items {
						if strings.HasPrefix(v.Name, "ubuntu-deployment") {
							podName = v.Name
							break
						}
					}

					for _, expectedResult := range tc.expectedResults {
						var stdout, stderr bytes.Buffer

						t.Log("running:", expectedResult.Commands)
						err = r.ExecInPod(
							ctx,
							workloadNamespace,
							podName,
							"ubuntu",
							expectedResult.Commands,
							&stdout,
							&stderr,
						)

						if expectedResult.Allowed {
							require.NoError(t, err)
						} else {
							require.Error(t, err)
							require.Empty(t, stdout.String())
							require.Contains(t, stderr.String(), "operation not permitted\n")
						}
					}

					// 3. Delete WorkloadSecurityPolicy
					err = r.Delete(ctx, &policy)
					require.NoError(t, err)

					err = wait.For(conditions.New(r).ResourceDeleted(&tragonv1alpha1.TracingPolicyNamespaced{
						ObjectMeta: metav1.ObjectMeta{
							Name:      policy.Name,
							Namespace: policy.Namespace,
						},
					}))
					require.NoError(t, err)
				}

				return ctx
			}).
		Teardown(func(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
			t.Log("uninstalling test resources")
			r := ctx.Value(key("client")).(*resources.Resources)
			err := decoder.DeleteWithManifestDir(
				ctx,
				r,
				"./testdata",
				"ubuntu-deployment.yaml",
				[]resources.DeleteOption{},
				decoder.MutateNamespace(workloadNamespace),
			)
			assert.NoError(t, err, "failed to delete test data")

			return ctx
		}).Feature()
}
