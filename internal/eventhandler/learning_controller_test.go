package eventhandler_test

import (
	"context"
	"fmt"
	"sync"

	securityv1alpha1 "github.com/neuvector/runtime-enforcer/api/v1alpha1"
	"github.com/neuvector/runtime-enforcer/internal/eventhandler"
	"github.com/neuvector/runtime-enforcer/internal/eventscraper"

	. "github.com/onsi/ginkgo/v2" //nolint:revive // Required for testing
	. "github.com/onsi/gomega"    //nolint:revive // Required for testing
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

var _ = Describe("Learning", func() {
	Context("When reconciling a resource", func() {
		ctx = context.Background()

		typeNamespacedName := types.NamespacedName{
			Name:      "ubuntu-deployment",
			Namespace: "default",
		}

		proposal := &securityv1alpha1.WorkloadSecurityPolicyProposal{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "deploy-ubuntu-deployment",
				Namespace: "default",
			},
			Spec: securityv1alpha1.WorkloadSecurityPolicyProposalSpec{
				Selector: &metav1.LabelSelector{
					MatchLabels: map[string]string{
						"app": "ubuntu",
					},
				},
			},
		}

		deployment := &appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{
				Name:      typeNamespacedName.Name,
				Namespace: typeNamespacedName.Namespace,
			},
			Spec: appsv1.DeploymentSpec{
				Selector: &metav1.LabelSelector{
					MatchLabels: map[string]string{
						"app": "ubuntu",
					},
				},
				Template: corev1.PodTemplateSpec{
					ObjectMeta: metav1.ObjectMeta{
						Name: "ubuntu",
						Labels: map[string]string{
							"app": "ubuntu",
						},
					},
					Spec: corev1.PodSpec{
						Containers: []corev1.Container{
							{
								Name:  "ubuntu",
								Image: "ubuntu",
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
				ObjectMeta: metav1.ObjectMeta{
					Name:      deployment.Name,
					Namespace: deployment.Namespace,
				},
			})).To(Succeed())
			Expect(k8sClient.Delete(ctx, &securityv1alpha1.WorkloadSecurityPolicyProposal{
				ObjectMeta: metav1.ObjectMeta{
					Name:      proposal.Name,
					Namespace: proposal.Namespace,
				},
			})).To(Succeed())
		})

		It("should learn container behavior correctly", func() {
			By("appending process list without duplicate and missing")
			// In this test, we create multiple reconcilers to simulate the behavior of multiple daemons/nodes.
			// The test case here is pretty lenient to prevent tests from broken randomly.
			const workerNum = 10
			const eventsToProcessNum = 10

			eventsToProcess := []eventscraper.KubeProcessInfo{}
			expectedAllowList := []string{}

			for i := range eventsToProcessNum {
				eventsToProcess = append(eventsToProcess, eventscraper.KubeProcessInfo{
					Namespace:      "default",
					ContainerName:  "ubuntu",
					ExecutablePath: fmt.Sprintf("/usr/bin/sleep%d", i),
					Workload:       "ubuntu-deployment",
					WorkloadKind:   "Deployment",
				})
				expectedAllowList = append(expectedAllowList, fmt.Sprintf("/usr/bin/sleep%d", i))
			}

			var wg sync.WaitGroup

			for i := range workerNum {
				workerFunc := func() {
					var err error
					var perWorkerClient client.Client
					name := fmt.Sprintf("worker%d", i)

					logf.Log.Info("worker started", "name", name)

					scheme := runtime.NewScheme()
					err = securityv1alpha1.AddToScheme(scheme)
					Expect(err).NotTo(HaveOccurred())

					perWorkerClient, err = client.New(cfg, client.Options{
						Scheme: scheme,
					})
					Expect(err).NotTo(HaveOccurred())

					reconciler := eventhandler.NewLearningReconciler(perWorkerClient, perWorkerClient.Scheme())

					for _, learningEvent := range eventsToProcess {
						var lastErr error
						for range 5 {
							if _, lastErr = reconciler.Reconcile(ctx, learningEvent); lastErr != nil {
								logf.Log.Info("error:", "error", lastErr)
							} else {
								lastErr = nil
								break
							}
						}
						Expect(lastErr).NotTo(HaveOccurred())
					}

					logf.Log.Info("worker finished", "name", name)
				}
				wg.Go(workerFunc)
			}
			wg.Wait()

			proposalResult := securityv1alpha1.WorkloadSecurityPolicyProposal{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "deploy-ubuntu-deployment",
					Namespace: "default",
				},
			}

			err := k8sClient.Get(ctx, types.NamespacedName{
				Namespace: proposalResult.Namespace,
				Name:      proposalResult.Name,
			}, &proposalResult)
			Expect(err).NotTo(HaveOccurred())

			Expect(proposalResult.Spec.Rules.Executables.Allowed).To(HaveLen(eventsToProcessNum))
			Expect(proposalResult.Spec.Rules.Executables.Allowed).To(ContainElements(expectedAllowList))
		})

		It("should correctly learn process behavior", func() {
			var err error

			const testNamespace = "default"
			const testResourceName = "ubuntu-deployment-2"
			const testProposalName = "deploy-ubuntu-deployment-2"

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
							ContainerName:  "ubuntu",
							ExecutablePath: "/usr/bin/sleep",
						},
						{
							Namespace:      testNamespace,
							Workload:       testResourceName,
							WorkloadKind:   "Deployment",
							ContainerName:  "ubuntu",
							ExecutablePath: "/usr/bin/bash",
						},
						{
							Namespace:      testNamespace,
							Workload:       testResourceName,
							WorkloadKind:   "Deployment",
							ContainerName:  "ubuntu",
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
							ContainerName:  "ubuntu",
							ExecutablePath: "/usr/bin/sleep",
						},
						{
							Namespace:      testNamespace,
							Workload:       testResourceName,
							WorkloadKind:   "Deployment",
							ContainerName:  "ubuntu",
							ExecutablePath: "/usr/bin/sleep",
						},
						{
							Namespace:      testNamespace,
							Workload:       testResourceName,
							WorkloadKind:   "Deployment",
							ContainerName:  "ubuntu",
							ExecutablePath: "/usr/bin/sleep",
						},
					},
					expectedResult: []string{
						"/usr/bin/sleep",
					},
				},
			}

			reconciler := eventhandler.NewLearningReconciler(k8sClient, k8sClient.Scheme())

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
				Expect(testProposal.Spec.Rules.Executables.Allowed).To(Equal(tc.expectedResult))

				Expect(k8sClient.Delete(ctx, &securityv1alpha1.WorkloadSecurityPolicyProposal{
					ObjectMeta: metav1.ObjectMeta{
						Name:      testProposal.Name,
						Namespace: testProposal.Namespace,
					},
				})).To(Succeed())
			}
		})

		It("should not learn process behavior when a policy proposal is labeled as ready", func() {
			const testNamespace = "default"
			const testResourceName = "ubuntu-deployment-3"
			const testProposalName = "deploy-ubuntu-deployment-3"

			var err error

			processEvents := []eventscraper.KubeProcessInfo{
				{
					Namespace:      testNamespace,
					Workload:       testResourceName,
					WorkloadKind:   "Deployment",
					ContainerName:  "ubuntu",
					ExecutablePath: "/usr/bin/sleep",
				},
				{
					Namespace:      testNamespace,
					Workload:       testResourceName,
					WorkloadKind:   "Deployment",
					ContainerName:  "ubuntu",
					ExecutablePath: "/usr/bin/bash",
				},
				{
					Namespace:      testNamespace,
					Workload:       testResourceName,
					WorkloadKind:   "Deployment",
					ContainerName:  "ubuntu",
					ExecutablePath: "/usr/bin/ls",
				},
			}

			reconciler := eventhandler.NewLearningReconciler(k8sClient, k8sClient.Scheme())

			testProposal := proposal.DeepCopy()
			testProposal.Namespace = testNamespace
			testProposal.Name = testProposalName
			labels := map[string]string{}
			labels[securityv1alpha1.ApprovalLabelKey] = "true"
			testProposal.SetLabels(labels)

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
			Expect(testProposal.Spec.Rules.Executables.Allowed).To(BeEmpty())

			Expect(k8sClient.Delete(ctx, &securityv1alpha1.WorkloadSecurityPolicyProposal{
				ObjectMeta: metav1.ObjectMeta{
					Name:      testProposal.Name,
					Namespace: testProposal.Namespace,
				},
			})).To(Succeed())
		})
	})
})
