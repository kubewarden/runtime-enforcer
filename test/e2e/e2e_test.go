package e2e_test

import (
	"bytes"
	"context"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/neuvector/runtime-enforcement/api/v1alpha1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"sigs.k8s.io/e2e-framework/pkg/envconf"
	"sigs.k8s.io/e2e-framework/pkg/features"
	"sigs.k8s.io/e2e-framework/third_party/helm"

	"sigs.k8s.io/e2e-framework/klient/decoder"
	"sigs.k8s.io/e2e-framework/klient/k8s"
	"sigs.k8s.io/e2e-framework/klient/k8s/resources"
	"sigs.k8s.io/e2e-framework/klient/wait"
	"sigs.k8s.io/e2e-framework/klient/wait/conditions"

	tragonv1alpha1 "github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type key string

func InstallRuntimeEnforcement(ctx context.Context, t *testing.T, config *envconf.Config) context.Context {
	t.Log("installing runtime-enforcement helm charts")
	manager := helm.New(config.KubeconfigFile())
	err := manager.RunInstall(helm.WithName("runtime-enforcement"),
		helm.WithNamespace(namespace),
		helm.WithChart("../../charts/runtime-enforcement/"),
		helm.WithWait(),
		helm.WithTimeout("3m"))

	assert.NoError(t, err, "runtime-enforcement helm chart is not installed correctly")
	return ctx
}

func InstallTetragon(ctx context.Context, t *testing.T, config *envconf.Config) context.Context {
	t.Log("installing tetragon helm charts")
	manager := helm.New(config.KubeconfigFile())

	err := manager.RunRepo(helm.WithArgs("add", ciliumRepo, "https://helm.cilium.io/"))
	require.NoError(t, err, "tetragon repo is not added correctly")

	err = manager.RunRepo(helm.WithArgs("update"))
	require.NoError(t, err, "tetragon repo is not updated correctly")

	err = manager.RunInstall(helm.WithChart(ciliumRepo+"/tetragon"),
		helm.WithName("tetragon"),
		helm.WithNamespace("kube-system"),
		helm.WithArgs("--set", "tetragonOperator.enabled=false", "--set", "crds.installMethod=helm"),
		helm.WithWait(),
		helm.WithTimeout("3m"))
	require.NoError(t, err, "tetragon helm chart is not installed correctly")

	return ctx
}

func TestInstallation(t *testing.T) {
	t.Log("test installation")

	feature := features.New("Custom Controller").
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
		Assess("check if operator was created",
			AssessResource("runtime-enforcement-controller-manager",
				namespace,
				&appsv1.Deployment{})).
		Assess("check if daemon was created",
			AssessResource("runtime-enforcement-daemon",
				namespace, &appsv1.DaemonSet{})).
		Assess("check if the workload security proposal is created for the ubuntu pod",
			func(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
				r := ctx.Value(key("client")).(*resources.Resources)

				var proposals v1alpha1.WorkloadSecurityPolicyProposalList

				err := r.WithNamespace("default").List(ctx, &proposals)
				require.NoError(t, err)

				found := false
				id := ""
			Exit:
				for _, v := range proposals.Items {
					if len(v.OwnerReferences) > 0 {
						if v.OwnerReferences[0].Name == "ubuntu-deployment" &&
							v.OwnerReferences[0].Kind == "Deployment" {
							id = v.Name
							found = true
							break Exit
						}
					}
				}

				assert.True(t, found, "there should be a workload group assigned for ubuntu-deployment Deployment")

				return context.WithValue(ctx, key("group"), id)
			}).
		Assess("make sure workload security policy proposal is created for ubuntu deployment",
			func(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
				id := ctx.Value(key("group")).(string)
				r := ctx.Value(key("client")).(*resources.Resources)

				t.Log("waiting for security policy proposal to be created: ", id)

				proposal := v1alpha1.WorkloadSecurityPolicyProposal{
					ObjectMeta: v1.ObjectMeta{
						Name:      id,
						Namespace: "default",
					},
				}

				t.Log("waiting for /usr/bin/sleep to be learned")

				err := wait.For(conditions.New(r).ResourceMatch(&proposal, func(object k8s.Object) bool {
					obj := object.(*v1alpha1.WorkloadSecurityPolicyProposal)

					return slices.Contains(obj.Spec.Rules.Executables.Allowed, "/usr/bin/sleep")
				}), wait.WithTimeout(time.Minute*3))
				require.NoError(t, err)

				return context.WithValue(ctx, key("proposal"), &proposal)
			}).
		Assess("create a security policy based on proposal and wait for Tetragon rules to be created",
			func(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
				t.Log("create a security policy")

				r := ctx.Value(key("client")).(*resources.Resources)
				proposal := ctx.Value(key("proposal")).(*v1alpha1.WorkloadSecurityPolicyProposal)

				policy := v1alpha1.WorkloadSecurityPolicy{
					TypeMeta: v1.TypeMeta{},
					ObjectMeta: v1.ObjectMeta{
						Name:      proposal.Name,
						Namespace: proposal.Namespace,
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
						Message:  "sleep",
						Tags:     []string{"sleep"},
					},
					Status: v1alpha1.WorkloadSecurityPolicyStatus{},
				}
				err := r.Create(ctx, &policy)
				require.NoError(t, err, "create policy")

				t.Log("waiting for the tetragon rule to be created: ", policy.Name)

				tp := tragonv1alpha1.TracingPolicyNamespaced{
					ObjectMeta: v1.ObjectMeta{
						Name:      policy.Name,
						Namespace: proposal.Namespace,
					},
				}

				err = wait.For(conditions.New(r).ResourceMatch(&tp, func(object k8s.Object) bool {
					obj := object.(*tragonv1alpha1.TracingPolicyNamespaced)

					return len(obj.Spec.KProbes) > 0
				}), wait.WithTimeout(time.Minute*3))
				require.NoError(t, err)
				assert.Len(t, "1", len(tp.Spec.KProbes))
				assert.Equal(t, []string{"sleep"}, tp.Spec.KProbes[0].Tags)
				assert.Equal(t, "[9] sleep", tp.Spec.KProbes[0].Message)

				return context.WithValue(ctx, key("policy"), &policy)
			}).
		Assess("check if pod exec will be blocked",
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

				err = r.ExecInPod(ctx, "default", podName, "ubuntu", []string{"bash"}, &stdout, &stderr)
				require.Error(t, err)
				require.Empty(t, stdout.String())
				require.Equal(t, "exec /usr/bin/bash: operation not permitted\n", stderr.String())

				return ctx
			}).
		Teardown(func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			manager := helm.New(cfg.KubeconfigFile())
			err := manager.RunRepo(helm.WithArgs("remove", ciliumRepo))
			require.NoError(t, err, "failed to apply test data")

			return ctx
		}).Feature()

	testEnv.Test(t, feature)
}
