package e2e_test

import (
	"bytes"
	"context"
	"slices"
	"strings"
	"testing"

	tragonv1alpha1 "github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/neuvector/runtime-enforcement/api/v1alpha1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
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
	"sigs.k8s.io/e2e-framework/third_party/helm"
)

func getEnforcementTest() types.Feature {
	return features.New("Enforcement").
		Setup(InstallRuntimeEnforcement).
		Setup(InstallTetragon).
		Setup(func(ctx context.Context, t *testing.T, config *envconf.Config) context.Context {
			t.Log("setup shared k8s client")

			r, err := resources.New(config.Client().RESTConfig())
			require.NoError(t, err, "failed to create controller runtime client")

			err = v1alpha1.AddToScheme(r.GetScheme())
			require.NoError(t, err)

			err = tragonv1alpha1.AddToScheme(r.GetScheme())
			require.NoError(t, err)

			return context.WithValue(ctx, key("client"), r)
		}).
		Setup(func(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
			t.Log("installing test Ubuntu deployment")

			r := ctx.Value(key("client")).(*resources.Resources)

			err := decoder.ApplyWithManifestDir(ctx, r, "./testdata", "*", []resources.CreateOption{})
			assert.NoError(t, err, "failed to apply test data")

			return ctx
		}).
		Assess("required resources become available",
			func(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
				var err error

				r := ctx.Value(key("client")).(*resources.Resources)

				err = wait.For(
					conditions.New(r).DeploymentAvailable(
						"runtime-enforcement-controller-manager",
						namespace,
					),
					wait.WithTimeout(DefaultTimeout),
				)
				require.NoError(t, err)

				err = wait.For(conditions.New(r).DaemonSetReady(
					&appsv1.DaemonSet{
						ObjectMeta: metav1.ObjectMeta{
							Name:      "runtime-enforcement-daemon",
							Namespace: namespace,
						},
					}),
					wait.WithTimeout(DefaultTimeout),
				)
				require.NoError(t, err)

				return ctx
			}).
		Assess("the workload security proposal is created successfully for the ubuntu pod",
			func(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
				r := ctx.Value(key("client")).(*resources.Resources)

				proposal := v1alpha1.WorkloadSecurityPolicyProposal{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "deploy-ubuntu-deployment",
						Namespace: "default", // to be consistent with test data.
					},
				}
				err := wait.For(conditions.New(r).ResourceMatch(
					&proposal,
					func(object k8s.Object) bool {
						obj := object.(*v1alpha1.WorkloadSecurityPolicyProposal)
						if obj.OwnerReferences[0].Name == "ubuntu-deployment" &&
							obj.OwnerReferences[0].Kind == "Deployment" {
							return true
						}
						return false
					}),
					wait.WithTimeout(DefaultTimeout),
				)
				require.NoError(t, err)

				return context.WithValue(ctx, key("group"), proposal.Name)
			}).
		Assess("the running process is learned",
			func(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
				id := ctx.Value(key("group")).(string)
				r := ctx.Value(key("client")).(*resources.Resources)

				t.Log("waiting for security policy proposal to be created: ", id)

				proposal := v1alpha1.WorkloadSecurityPolicyProposal{
					ObjectMeta: metav1.ObjectMeta{
						Name:      id,
						Namespace: "default", // to be consistent with test data.
					},
				}

				// There are two categories of processes to be learned:
				// 1. /usr/bin/bash: the container entrypoint.
				// 2. /usr/bin/sleep & /usr/bin/ls: the commands the container executes
				t.Log("waiting for processes to be learned")

				err := wait.For(conditions.New(r).ResourceMatch(
					&proposal,
					func(_ k8s.Object) bool {
						if slices.Contains(proposal.Spec.Rules.Executables.Allowed, "/usr/bin/bash") &&
							slices.Contains(proposal.Spec.Rules.Executables.Allowed, "/usr/bin/ls") &&
							slices.Contains(proposal.Spec.Rules.Executables.Allowed, "/usr/bin/sleep") {
							return true
						}

						return false
					}),
					wait.WithTimeout(DefaultTimeout),
				)
				require.NoError(t, err)

				return context.WithValue(ctx, key("proposal"), &proposal)
			}).
		Assess("a proposal is promoted to a security policy and its Tetragon rules is created",
			func(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
				t.Log("create a security policy")

				r := ctx.Value(key("client")).(*resources.Resources)
				proposal := ctx.Value(key("proposal")).(*v1alpha1.WorkloadSecurityPolicyProposal)

				policy := v1alpha1.WorkloadSecurityPolicy{
					ObjectMeta: metav1.ObjectMeta{
						Name:      proposal.ObjectMeta.Name,
						Namespace: proposal.ObjectMeta.Namespace,
					},
					Spec: v1alpha1.WorkloadSecurityPolicySpec{
						Mode:     "protect",
						Selector: proposal.Spec.Selector,
						Rules: v1alpha1.WorkloadSecurityPolicyRules{
							Executables: v1alpha1.WorkloadSecurityPolicyExecutables{
								Allowed:         proposal.Spec.Rules.Executables.Allowed,
								AllowedPrefixes: proposal.Spec.Rules.Executables.AllowedPrefixes,
							},
						},
						Severity: 9,
						Message:  "test-policy",
						Tags:     []string{"test-policy"},
					},
				}
				err := r.Create(ctx, &policy)
				require.NoError(t, err, "create policy")

				t.Log("waiting for the tetragon rule to be created: ", policy.Name)

				tp := tragonv1alpha1.TracingPolicyNamespaced{
					ObjectMeta: metav1.ObjectMeta{
						Name:      policy.Name,
						Namespace: proposal.Namespace,
					},
				}

				err = wait.For(conditions.New(r).ResourceMatch(&tp, func(_ k8s.Object) bool {
					return true
				}), wait.WithTimeout(DefaultTimeout))
				require.NoError(t, err)
				assert.Len(t, "1", len(tp.Spec.KProbes))
				assert.Equal(t, []string{"test-policy"}, tp.Spec.KProbes[0].Tags)
				assert.Equal(t, "[9] test-policy", tp.Spec.KProbes[0].Message)

				return context.WithValue(ctx, key("policy"), &policy)
			}).
		Assess("pod exec will be blocked",
			func(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
				r := ctx.Value(key("client")).(*resources.Resources)

				var podName string
				var pods corev1.PodList
				err := r.WithNamespace("default").List(ctx, &pods)
				require.NoError(t, err)

				for _, v := range pods.Items {
					if strings.HasPrefix(v.Name, "ubuntu-deployment") {
						podName = v.Name
						break
					}
				}

				var stdout, stderr bytes.Buffer

				err = r.ExecInPod(ctx, "default", podName, "ubuntu", []string{"mkdir"}, &stdout, &stderr)
				require.Error(t, err)
				require.Empty(t, stdout.String())
				require.Equal(t, "exec /usr/bin/mkdir: operation not permitted\n", stderr.String())

				return ctx
			}).
		Assess("delete security policy", func(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
			r := ctx.Value(key("client")).(*resources.Resources)
			policy := ctx.Value(key("policy")).(*v1alpha1.WorkloadSecurityPolicy)

			err := r.Delete(ctx, policy)
			require.NoError(t, err)

			err = wait.For(conditions.New(r).ResourceDeleted(&tragonv1alpha1.TracingPolicyNamespaced{
				ObjectMeta: metav1.ObjectMeta{
					Name:      policy.Name,
					Namespace: policy.Namespace,
				},
			}))
			require.NoError(t, err)

			return ctx
		}).
		Assess("a policy is promoted to a cluster policy and its Tetragon rules is created",
			func(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
				t.Log("create a cluster security policy")

				r := ctx.Value(key("client")).(*resources.Resources)
				policy := ctx.Value(key("policy")).(*v1alpha1.WorkloadSecurityPolicy)

				clusterPolicy := v1alpha1.ClusterWorkloadSecurityPolicy{
					TypeMeta: metav1.TypeMeta{},
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-policy",
					},
					Spec:   policy.Spec,
					Status: v1alpha1.WorkloadSecurityPolicyStatus{},
				}
				err := r.Create(ctx, &clusterPolicy)
				require.NoError(t, err, "create policy")

				t.Log("waiting for the tetragon rule to be created: ", clusterPolicy.Name)

				tp := tragonv1alpha1.TracingPolicy{
					ObjectMeta: metav1.ObjectMeta{
						Name: clusterPolicy.Name,
					},
				}

				err = wait.For(conditions.New(r).ResourceMatch(&tp, func(_ k8s.Object) bool {
					return true
				}), wait.WithTimeout(DefaultTimeout))
				require.NoError(t, err)

				assert.Len(t, "1", len(tp.Spec.KProbes))
				assert.Equal(t, []string{"test-policy"}, tp.Spec.KProbes[0].Tags)
				assert.Equal(t, "[9] test-policy", tp.Spec.KProbes[0].Message)

				return context.WithValue(ctx, key("clusterPolicy"), &clusterPolicy)
			}).
		Assess("pod exec will still be blocked",
			func(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
				r := ctx.Value(key("client")).(*resources.Resources)

				var podName string
				var pods corev1.PodList
				err := r.WithNamespace("default").List(ctx, &pods)
				require.NoError(t, err)

				for _, v := range pods.Items {
					if strings.HasPrefix(v.Name, "ubuntu-deployment") {
						podName = v.Name
						break
					}
				}

				var stdout, stderr bytes.Buffer

				err = r.ExecInPod(ctx, "default", podName, "ubuntu", []string{"mkdir"}, &stdout, &stderr)
				require.Error(t, err)
				require.Empty(t, stdout.String())
				require.Equal(t, "exec /usr/bin/mkdir: operation not permitted\n", stderr.String())

				return ctx
			}).
		Assess("cluster security policy is deleted", func(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
			r := ctx.Value(key("client")).(*resources.Resources)
			clusterPolicy := ctx.Value(key("clusterPolicy")).(*v1alpha1.ClusterWorkloadSecurityPolicy)

			err := r.Delete(ctx, clusterPolicy)
			require.NoError(t, err)

			err = wait.For(conditions.New(r).ResourceDeleted(&tragonv1alpha1.TracingPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      clusterPolicy.Name,
					Namespace: clusterPolicy.Namespace,
				},
			}))
			require.NoError(t, err)

			return ctx
		}).
		Teardown(func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			manager := helm.New(cfg.KubeconfigFile())
			err := manager.RunRepo(helm.WithArgs("remove", ciliumRepo))
			require.NoError(t, err, "failed to apply test data")

			return ctx
		}).Feature()
}
