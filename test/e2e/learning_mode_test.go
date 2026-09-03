package e2e_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/kubewarden/runtime-enforcer/api/v1alpha1"
	"github.com/kubewarden/runtime-enforcer/internal/eventhandler/proposalutils"
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

const proposalIsNotCreatedTimeout = 30 * time.Second

func getLearningModeTest() types.Feature {
	return features.New("LearningMode").
		Setup(SetupSharedK8sClient).
		Setup(SetupTestNamespace).
		Setup(func(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
			t.Log("installing test resources")

			r := getClient(ctx)

			err := decoder.ApplyWithManifestDir(
				ctx,
				r,
				"./testdata",
				"*",
				[]resources.CreateOption{},
				decoder.MutateNamespace(getNamespace(ctx)),
			)
			assert.NoError(t, err, "failed to apply test data")

			return ctx
		}).
		Assess("required resources become available", IfRequiredResourcesAreCreated).
		Assess("the workload policy proposal is created successfully for each supported resource",
			func(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
				r := getClient(ctx)

				testdata := os.DirFS("./testdata")

				testcases := map[string]struct {
					ParseFunc func() k8s.Object
				}{
					"DaemonSet": {
						ParseFunc: func() k8s.Object {
							var daemonset appsv1.DaemonSet
							err := decoder.DecodeFile(testdata, "opensuse-daemonset.yaml", &daemonset)
							require.NoError(t, err)
							return &daemonset
						},
					},
					"Deployment": {
						ParseFunc: func() k8s.Object {
							var deployment appsv1.Deployment
							err := decoder.DecodeFile(testdata, "opensuse-deployment.yaml", &deployment)
							require.NoError(t, err)
							return &deployment
						},
					},
					"StatefulSet": {
						ParseFunc: func() k8s.Object {
							var statefulset appsv1.StatefulSet
							err := decoder.DecodeFile(testdata, "opensuse-statefulset.yaml", &statefulset)
							require.NoError(t, err)
							return &statefulset
						},
					},
					"Job": {
						ParseFunc: func() k8s.Object {
							var job batchv1.Job
							err := decoder.DecodeFile(testdata, "opensuse-job.yaml", &job)
							require.NoError(t, err)
							return &job
						},
					},
					"CronJob": {
						ParseFunc: func() k8s.Object {
							var cronjob batchv1.CronJob
							err := decoder.DecodeFile(testdata, "opensuse-cronjob.yaml", &cronjob)
							require.NoError(t, err)
							return &cronjob
						},
					},
				}

				for kind, tc := range testcases {
					obj := tc.ParseFunc()
					t.Log("verifying if a proposal resource can be created: ", kind)

					proposalName, err := proposalutils.GetWorkloadPolicyProposalName(kind, obj.GetName())
					require.NoError(t, err)

					proposal := v1alpha1.WorkloadPolicyProposal{
						ObjectMeta: metav1.ObjectMeta{
							Name:      proposalName,
							Namespace: getNamespace(ctx), // to be consistent with test data.
						},
					}
					err = wait.For(conditions.New(r).ResourceMatch(
						&proposal,
						func(_ k8s.Object) bool {
							return true
						}),
						wait.WithTimeout(defaultOperationTimeout),
					)
					require.NoError(t, err)
					require.Len(t, proposal.OwnerReferences, 1)
					require.Equal(t, obj.GetName(), proposal.OwnerReferences[0].Name)
					require.Equal(t, obj.GetObjectKind().GroupVersionKind().Kind, proposal.OwnerReferences[0].Kind)

					t.Log("verifying if processes can be learned")
					err = wait.For(conditions.New(r).ResourceMatch(
						&proposal,
						func(_ k8s.Object) bool {
							if proposal.Spec.RulesByContainer == nil {
								return false
							}

							t.Log("proposal: ", proposal)

							rules, ok := proposal.Spec.RulesByContainer["opensuse"]
							if !ok {
								return false
							}

							return verifyOpensuseLearnedProcesses(rules.Executables.Allowed)
						}),
						wait.WithTimeout(defaultOperationTimeout),
					)
					require.NoError(t, err)
				}

				return ctx
			}).
		Teardown(func(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
			t.Log("uninstalling test resources")

			r := getClient(ctx)

			err := decoder.DeleteWithManifestDir(
				ctx,
				r,
				"./testdata",
				"*",
				[]resources.DeleteOption{
					resources.WithDeletePropagation("Foreground"),
				},
				decoder.MutateNamespace(getNamespace(ctx)),
			)
			assert.NoError(t, err, "failed to delete test data")

			return ctx
		}).Feature()
}

func getNoLearningModeTest() types.Feature {
	return features.New("learning disabled in namespace").
		Setup(SetupSharedK8sClient).
		Assess("create a namespace without the learning label",
			func(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
				disabledNS := envconf.RandomName("learning-disabled-ns", 32)
				t.Logf("creating a namespace without the selector: %s", disabledNS)
				r := getClient(ctx)
				require.NoError(t, r.Create(ctx, &corev1.Namespace{
					Name: disabledNS,
				}))
				return context.WithValue(ctx, key("namespace"), disabledNS)
			}).
		Assess("required resources become available", IfRequiredResourcesAreCreated).
		Assess("install opensuse deployment in disabled namespace", func(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
			createAndWaitOpensuseDeployment(ctx, t)
			return ctx
		}).
		Assess("no proposal for opensuse deployment", func(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
			proposalName, err := proposalutils.GetWorkloadPolicyProposalName("Deployment", opensuseDeploymentName)
			require.NoError(t, err)

			proposal := v1alpha1.WorkloadPolicyProposal{
				Name:      proposalName,
				Namespace: getNamespace(ctx),
			}

			// we want to be sure the proposal is not created so we need to try several times.
			r := getClient(ctx)
			err = wait.For(conditions.New(r).ResourceMatch(
				&proposal,
				func(obj k8s.Object) bool {
					p, ok := obj.(*v1alpha1.WorkloadPolicyProposal)
					if !ok || p == nil {
						return false
					}
					return true
				}),
				wait.WithTimeout(proposalIsNotCreatedTimeout),
			)
			require.Error(
				t,
				err,
				"proposal should not be created in namespace %s",
				getNamespace(ctx),
			)
			return ctx
		}).
		Teardown(func(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
			deleteOpensuseDeployment(ctx, t)
			return ctx
		}).Feature()
}
