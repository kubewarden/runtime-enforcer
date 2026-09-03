package eventhandler_test

import (
	"context"
	"fmt"

	securityv1alpha1 "github.com/kubewarden/runtime-enforcer/api/v1alpha1"
	"github.com/kubewarden/runtime-enforcer/internal/eventhandler"
	"github.com/kubewarden/runtime-enforcer/internal/eventscraper"
	"github.com/kubewarden/runtime-enforcer/internal/types/policymode"
	"golang.org/x/sync/errgroup"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/labels"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

func newTestLearningReconciler(client client.Client, selector labels.Selector) *eventhandler.LearningReconciler {
	reconciler := eventhandler.NewLearningReconciler(client, selector)
	// we don't want owner references to be added in tests because the webhook won't complete it and the api server will reject the resource creation with a partial ownerReference.
	reconciler.OwnerRefEnricher = func(_ *securityv1alpha1.WorkloadPolicyProposal, _ string, _ string) {}
	return reconciler
}

var _ = Describe("Learning", func() {
	Context("When reconciling a resource", func() {
		ctx = context.Background()

		typeNamespacedName := types.NamespacedName{
			Name:      "opensuse-deployment",
			Namespace: "default",
		}

		proposal := &securityv1alpha1.WorkloadPolicyProposal{
			Name:      "deploy-opensuse-deployment",
			Namespace: "default",
			Spec:      securityv1alpha1.WorkloadPolicyProposalSpec{},
		}

		defaultNamespaceSelector := labels.SelectorFromSet(labels.Set{
			"kubernetes.io/metadata.name": "default",
		})

		deployment := &appsv1.Deployment{
			Name:      typeNamespacedName.Name,
			Namespace: typeNamespacedName.Namespace,
			Spec: appsv1.DeploymentSpec{
				Selector: &metav1.LabelSelector{
					MatchLabels: map[string]string{
						"app": "opensuse",
					},
				},
				Template: corev1.PodTemplateSpec{
					ObjectMeta: metav1.ObjectMeta{
						Name: "opensuse",
						Labels: map[string]string{
							"app": "opensuse",
						},
					},
					Spec: corev1.PodSpec{
						Containers: []corev1.Container{
							{
								Name:  "opensuse",
								Image: "opensuse",
							},
						},
					},
				},
			},
		}

		BeforeEach(func() {
			Expect(k8sClient.Create(ctx, deployment.DeepCopy())).To(Succeed())
			Expect(k8sClient.Create(ctx, proposal.DeepCopy())).To(Succeed())
		})

		AfterEach(func() {
			Expect(k8sClient.Delete(ctx, &appsv1.Deployment{
				Name:      deployment.Name,
				Namespace: deployment.Namespace,
			})).To(Succeed())
			Expect(k8sClient.Delete(ctx, &securityv1alpha1.WorkloadPolicyProposal{
				Name:      proposal.Name,
				Namespace: proposal.Namespace,
			})).To(Succeed())
		})

		It("should learn without duplicates", func() {
			// In this test, we create multiple reconcilers to simulate the behavior of multiple daemons/nodes.
			// The test case here is pretty lenient to prevent tests from broken randomly.
			const workerNum = 10
			const eventsToProcessNum = 10

			eventsToProcess := []eventscraper.KubeProcessInfo{}
			expectedAllowList := []string{}

			for i := range eventsToProcessNum {
				eventsToProcess = append(eventsToProcess, eventscraper.KubeProcessInfo{
					Namespace:      "default",
					ContainerName:  "opensuse",
					ExecutablePath: fmt.Sprintf("/usr/bin/sleep%d", i),
					Workload:       "opensuse-deployment",
					WorkloadKind:   "Deployment",
				})
				expectedAllowList = append(expectedAllowList, fmt.Sprintf("/usr/bin/sleep%d", i))
			}

			g, groupCtx := errgroup.WithContext(ctx)

			for i := range workerNum {
				index := i
				g.Go(func() error {
					var err error
					var ret ctrl.Result
					var perWorkerClient client.Client
					name := fmt.Sprintf("worker%d", index)
					logf.Log.Info("worker started", "name", name)

					scheme := runtime.NewScheme()
					err = securityv1alpha1.AddToScheme(scheme)
					if err != nil {
						return fmt.Errorf("failed to add scheme: %w", err)
					}
					err = corev1.AddToScheme(scheme)
					if err != nil {
						return fmt.Errorf("failed to add scheme: %w", err)
					}

					perWorkerClient, err = client.New(cfg, client.Options{
						Scheme: scheme,
					})
					if err != nil {
						return fmt.Errorf("failed to create client: %w", err)
					}

					reconciler := newTestLearningReconciler(perWorkerClient, defaultNamespaceSelector)
					for _, learningEvent := range eventsToProcess {
						for {
							// with the internal ratelimiter, the learning controller would return RequeueAfter instead of a conflict error.
							ret, err = reconciler.Reconcile(groupCtx, learningEvent)
							if err == nil && ret.RequeueAfter == 0 {
								// This means the item is correctly written.
								break
							}
							if err != nil {
								return err
							}
						}
					}
					logf.Log.Info("worker finished", "name", name)
					return nil
				})
			}

			if err := g.Wait(); err != nil {
				Expect(err).NotTo(HaveOccurred())
			}

			proposalResult := securityv1alpha1.WorkloadPolicyProposal{
				Name:      "deploy-opensuse-deployment",
				Namespace: "default",
			}

			err := k8sClient.Get(ctx, types.NamespacedName{
				Namespace: proposalResult.Namespace,
				Name:      proposalResult.Name,
			}, &proposalResult)
			Expect(err).NotTo(HaveOccurred())

			rules := proposalResult.Spec.RulesByContainer["opensuse"]

			Expect(rules.Executables.Allowed).To(HaveLen(eventsToProcessNum))
			Expect(rules.Executables.Allowed).To(ContainElements(expectedAllowList))
		})

		It("should correctly learn process behavior", func() {
			var err error

			const testNamespace = "default"
			const testResourceName = "opensuse-deployment-2"
			const testProposalName = "deploy-opensuse-deployment-2"

			tcs := []struct {
				processEvents  []eventscraper.KubeProcessInfo
				expectedResult []string
			}{
				{
					processEvents: []eventscraper.KubeProcessInfo{
						{
							Namespace:      testNamespace,
							Workload:       testResourceName,
							WorkloadKind:   "Deployment",
							ContainerName:  "opensuse",
							ExecutablePath: "/usr/bin/sleep",
						},
						{
							Namespace:      testNamespace,
							Workload:       testResourceName,
							WorkloadKind:   "Deployment",
							ContainerName:  "opensuse",
							ExecutablePath: "/usr/bin/bash",
						},
						{
							Namespace:      testNamespace,
							Workload:       testResourceName,
							WorkloadKind:   "Deployment",
							ContainerName:  "opensuse",
							ExecutablePath: "/usr/bin/ls",
						},
					},
					expectedResult: []string{
						"/usr/bin/sleep",
						"/usr/bin/bash",
						"/usr/bin/ls",
					},
				},
				{
					processEvents: []eventscraper.KubeProcessInfo{
						{
							Namespace:      testNamespace,
							Workload:       testResourceName,
							WorkloadKind:   "Deployment",
							ContainerName:  "opensuse",
							ExecutablePath: "/usr/bin/sleep",
						},
						{
							Namespace:      testNamespace,
							Workload:       testResourceName,
							WorkloadKind:   "Deployment",
							ContainerName:  "opensuse",
							ExecutablePath: "/usr/bin/sleep",
						},
						{
							Namespace:      testNamespace,
							Workload:       testResourceName,
							WorkloadKind:   "Deployment",
							ContainerName:  "opensuse",
							ExecutablePath: "/usr/bin/sleep",
						},
					},
					expectedResult: []string{
						"/usr/bin/sleep",
					},
				},
			}

			reconciler := newTestLearningReconciler(k8sClient, defaultNamespaceSelector)

			for _, tc := range tcs {
				// Create an empty policy proposal
				testProposal := proposal.DeepCopy()
				testProposal.Namespace = testNamespace
				testProposal.Name = testProposalName
				Expect(k8sClient.Create(ctx, testProposal)).To(Succeed())

				for _, learningEvent := range tc.processEvents {
					var result ctrl.Result
					result, err = reconciler.Reconcile(ctx, learningEvent)
					Expect(err).NotTo(HaveOccurred())
					Expect(result).To(Equal(ctrl.Result{}))
				}

				err = k8sClient.Get(ctx, types.NamespacedName{
					Namespace: testNamespace,
					Name:      testProposalName,
				}, testProposal)
				Expect(err).NotTo(HaveOccurred())
				Expect(
					testProposal.Spec.RulesByContainer["opensuse"].Executables.Allowed,
				).To(ContainElements(tc.expectedResult))

				Expect(k8sClient.Delete(ctx, &securityv1alpha1.WorkloadPolicyProposal{
					Name:      testProposal.Name,
					Namespace: testProposal.Namespace,
				})).To(Succeed())
			}
		})

		It("should not learn process behavior when a policy proposal is labeled as ready", func() {
			const testNamespace = "default"
			const testResourceName = "opensuse-deployment-3"
			const testProposalName = "deploy-opensuse-deployment-3"

			var err error

			processEvents := []eventscraper.KubeProcessInfo{
				{
					Namespace:      testNamespace,
					Workload:       testResourceName,
					WorkloadKind:   "Deployment",
					ContainerName:  "opensuse",
					ExecutablePath: "/usr/bin/sleep",
				},
				{
					Namespace:      testNamespace,
					Workload:       testResourceName,
					WorkloadKind:   "Deployment",
					ContainerName:  "opensuse",
					ExecutablePath: "/usr/bin/bash",
				},
				{
					Namespace:      testNamespace,
					Workload:       testResourceName,
					WorkloadKind:   "Deployment",
					ContainerName:  "opensuse",
					ExecutablePath: "/usr/bin/ls",
				},
			}

			reconciler := eventhandler.NewLearningReconciler(k8sClient, defaultNamespaceSelector)

			testProposal := proposal.DeepCopy()
			testProposal.Namespace = testNamespace
			testProposal.Name = testProposalName
			testProposal.SetPromotionLabel(policymode.MonitorString)
			Expect(k8sClient.Create(ctx, testProposal)).To(Succeed())

			for _, learningEvent := range processEvents {
				var result ctrl.Result
				result, err = reconciler.Reconcile(ctx, learningEvent)
				Expect(err).NotTo(HaveOccurred())
				Expect(result).To(Equal(ctrl.Result{}))
			}

			err = k8sClient.Get(ctx, types.NamespacedName{
				Namespace: testNamespace,
				Name:      testProposalName,
			}, testProposal)
			Expect(err).NotTo(HaveOccurred())
			Expect(testProposal.Spec.RulesByContainer).To(BeNil())

			Expect(k8sClient.Delete(ctx, &securityv1alpha1.WorkloadPolicyProposal{
				Name:      testProposal.Name,
				Namespace: testProposal.Namespace,
			})).To(Succeed())
		})

		It("should not learn process behavior when a WorkloadPolicy already exists", func() {
			const testNamespace = "default"
			const testResourceName = "opensuse-deployment-4"
			const testProposalName = "deploy-opensuse-deployment-4"

			processEvents := []eventscraper.KubeProcessInfo{
				{
					Namespace:      testNamespace,
					Workload:       testResourceName,
					WorkloadKind:   "Deployment",
					ContainerName:  "opensuse",
					ExecutablePath: "/usr/bin/sleep",
				},
				{
					Namespace:      testNamespace,
					Workload:       testResourceName,
					WorkloadKind:   "Deployment",
					ContainerName:  "opensuse",
					ExecutablePath: "/usr/bin/ls",
				},
			}

			reconciler := eventhandler.NewLearningReconciler(k8sClient, defaultNamespaceSelector)

			workloadPolicy := &securityv1alpha1.WorkloadPolicy{
				Name:      testProposalName,
				Namespace: testNamespace,
				Spec: securityv1alpha1.WorkloadPolicySpec{
					Mode: "monitor",
				},
			}
			Expect(workloadPolicy.SetPromotedLabel(testProposalName)).To(Succeed())
			Expect(k8sClient.Create(ctx, workloadPolicy)).To(Succeed())

			for _, learningEvent := range processEvents {
				var result ctrl.Result
				var err error
				result, err = reconciler.Reconcile(ctx, learningEvent)
				Expect(err).NotTo(HaveOccurred())
				Expect(result).To(Equal(ctrl.Result{}))
			}

			// The learning reconciler should not recreate the proposal while the policy exists.
			proposalResult := &securityv1alpha1.WorkloadPolicyProposal{
				Name:      testProposalName,
				Namespace: testNamespace,
			}
			err := k8sClient.Get(ctx, types.NamespacedName{
				Namespace: testNamespace,
				Name:      testProposalName,
			}, proposalResult)
			Expect(apierrors.IsNotFound(err)).To(BeTrue())

			Expect(k8sClient.Delete(ctx, workloadPolicy)).To(Succeed())
		})

		When("namespace does not match selector", func() {
			It("should skip reconciliation and not create resources", func(ctx context.Context) {
				By("Creating a reconciler with a namespace selector")
				selector := labels.Set{
					"env": "testing",
				}.AsSelector()
				reconciler := newTestLearningReconciler(k8sClient, selector)

				By("Creating a namespace that does not match the selector")
				namespace := &corev1.Namespace{
					Name: "unmatched-namespace",
					Labels: map[string]string{
						"env": "development",
					},
				}
				Expect(k8sClient.Create(ctx, namespace)).To(Succeed())

				By("Reconciling a namespace that does not match the selector")
				_, err := reconciler.Reconcile(ctx, eventscraper.KubeProcessInfo{
					Namespace:      namespace.Name,
					Workload:       deployment.Name,
					WorkloadKind:   "Deployment",
					ContainerName:  "opensuse",
					ExecutablePath: "/usr/bin/sleep",
				})
				Expect(err).NotTo(HaveOccurred())

				By("Verifying no WorkloadPolicyProposal is created")
				var proposalList securityv1alpha1.WorkloadPolicyProposalList
				Expect(k8sClient.List(ctx, &proposalList, client.InNamespace(namespace.Name))).To(Succeed())
				Expect(proposalList.Items).To(BeEmpty())

				Expect(k8sClient.Delete(ctx, namespace)).To(Succeed())
			})
		})
	})
})
