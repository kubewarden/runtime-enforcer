package e2e_test

import (
	"context"
	"os"
	"slices"
	"testing"

	"github.com/neuvector/runtime-enforcement/api/v1alpha1"
	"github.com/neuvector/runtime-enforcement/internal/policy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
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

func getLearningModeTest() types.Feature {
	workloadNamespace := envconf.RandomName("learning-namespace", 32)

	return features.New("LearningMode").
		Setup(SetupSharedK8sClient).
		Setup(func(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
			t.Log("creating test namespace")
			r := ctx.Value(key("client")).(*resources.Resources)

			namespace := corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: workloadNamespace}}

			err := r.Create(ctx, &namespace)
			assert.NoError(t, err, "failed to create test namespace")

			return ctx
		}).
		Setup(func(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
			t.Log("installing test resources")

			r := ctx.Value(key("client")).(*resources.Resources)

			err := decoder.ApplyWithManifestDir(
				ctx,
				r,
				"./testdata",
				"*",
				[]resources.CreateOption{},
				decoder.MutateNamespace(workloadNamespace),
			)
			assert.NoError(t, err, "failed to apply test data")

			return ctx
		}).
		Assess("required resources become available", IfRequiredResourcesAreCreated).
		Assess("the workload security proposal is created successfully for each supported resource",
			func(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
				r := ctx.Value(key("client")).(*resources.Resources)

				testdata := os.DirFS("./testdata")

				testcases := map[string]struct {
					ParseFunc func() k8s.Object
				}{
					"DaemonSet": {
						ParseFunc: func() k8s.Object {
							var daemonset appsv1.DaemonSet
							err := decoder.DecodeFile(testdata, "ubuntu-daemonset.yaml", &daemonset)
							require.NoError(t, err)
							return &daemonset
						},
					},
					"Deployment": {
						ParseFunc: func() k8s.Object {
							var deployment appsv1.Deployment
							err := decoder.DecodeFile(testdata, "ubuntu-deployment.yaml", &deployment)
							require.NoError(t, err)
							return &deployment
						},
					},
					"ReplicaSet": {
						ParseFunc: func() k8s.Object {
							var replicaset appsv1.ReplicaSet
							err := decoder.DecodeFile(testdata, "ubuntu-replicaset.yaml", &replicaset)
							require.NoError(t, err)
							return &replicaset
						},
					},
					"StatefulSet": {
						ParseFunc: func() k8s.Object {
							var statefulset appsv1.StatefulSet
							err := decoder.DecodeFile(testdata, "ubuntu-statefulset.yaml", &statefulset)
							require.NoError(t, err)
							return &statefulset
						},
					},
					"Job": {
						ParseFunc: func() k8s.Object {
							var job batchv1.Job
							err := decoder.DecodeFile(testdata, "ubuntu-job.yaml", &job)
							require.NoError(t, err)
							return &job
						},
					},
					// "ubuntu-cronjob.yaml",
				}

				for kind, tc := range testcases {
					obj := tc.ParseFunc()
					t.Log("verifying if a proposal resource can be created: ", kind)

					proposalName, err := policy.GetWorkloadSecurityPolicyProposalName(kind, obj.GetName())
					require.NoError(t, err)

					proposal := v1alpha1.WorkloadSecurityPolicyProposal{
						ObjectMeta: metav1.ObjectMeta{
							Name:      proposalName,
							Namespace: workloadNamespace, // to be consistent with test data.
						},
					}
					err = wait.For(conditions.New(r).ResourceMatch(
						&proposal,
						func(_ k8s.Object) bool {
							return true
						}),
						wait.WithTimeout(DefaultTimeout),
					)
					require.NoError(t, err)
					require.Len(t, proposal.OwnerReferences, 1)
					require.Equal(t, obj.GetName(), proposal.OwnerReferences[0].Name)
					require.Equal(t, obj.GetObjectKind().GroupVersionKind().Kind, proposal.OwnerReferences[0].Kind)

					t.Log("verifying if processes can be learned")
					err = wait.For(conditions.New(r).ResourceMatch(
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
				"*",
				[]resources.DeleteOption{},
				decoder.MutateNamespace(workloadNamespace),
			)
			assert.NoError(t, err, "failed to delete test data")

			return ctx
		}).Feature()
}
