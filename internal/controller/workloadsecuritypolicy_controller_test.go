package controller_test

import (
	"context"

	tragonv1alpha1 "github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	. "github.com/onsi/ginkgo/v2" //nolint:revive // Required for testing
	. "github.com/onsi/gomega"    //nolint:revive // Required for testing
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	securityv1alpha1 "github.com/neuvector/runtime-enforcer/api/v1alpha1"
	"github.com/neuvector/runtime-enforcer/internal/controller"
)

var _ = Describe("WorkloadSecurityPolicy Controller", func() {
	Context("When reconciling a resource", func() {
		const resourceName = "test-resource"

		ctx = context.Background()

		typeNamespacedName := types.NamespacedName{
			Name:      resourceName,
			Namespace: "default",
		}

		BeforeEach(func() {
			By("creating the custom resource for the Kind WorkloadSecurityPolicy")
			resource := &securityv1alpha1.WorkloadSecurityPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      resourceName,
					Namespace: "default",
				},
				Spec: securityv1alpha1.WorkloadSecurityPolicySpec{
					Mode: "monitor",
					Selector: &metav1.LabelSelector{
						MatchLabels: map[string]string{
							"app": "ubuntu",
						},
					},
					Rules: securityv1alpha1.WorkloadSecurityPolicyRules{
						Executables: securityv1alpha1.WorkloadSecurityPolicyExecutables{
							Allowed: []string{
								"/usr/bin/sleep",
							},
							AllowedPrefixes: []string{
								"/bin/",
							},
						},
					},
					Severity: 10,
					Tags: []string{
						"tag",
					},
					Message: "TEST_RULE",
				},
			}
			Expect(k8sClient.Create(ctx, resource)).To(Succeed())
		})

		AfterEach(func() {
			resource := &securityv1alpha1.WorkloadSecurityPolicy{}
			err := k8sClient.Get(ctx, typeNamespacedName, resource)
			Expect(err).NotTo(HaveOccurred())

			By("Cleanup the specific resource instance WorkloadSecurityPolicy")
			Expect(k8sClient.Delete(ctx, resource)).To(Succeed())
		})

		It("should successfully reconcile the resource", func() {
			By("Reconciling the created resource")

			resource := &securityv1alpha1.WorkloadSecurityPolicy{}
			err := k8sClient.Get(ctx, typeNamespacedName, resource)
			Expect(err).NotTo(HaveOccurred())

			controllerReconciler := &controller.WorkloadSecurityPolicyReconciler{
				Client: k8sClient,
				Scheme: k8sClient.Scheme(),
			}

			_, err = controllerReconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})
			Expect(err).NotTo(HaveOccurred())

			var tracingpolicy tragonv1alpha1.TracingPolicyNamespaced

			// Getting TracingPolicyNamespaced with the same name.
			err = k8sClient.Get(ctx, typeNamespacedName, &tracingpolicy)
			Expect(err).NotTo(HaveOccurred())

			Expect(tracingpolicy.Spec.PodSelector.MatchLabels).To(Equal(resource.Spec.Selector.MatchLabels))
			Expect(tracingpolicy.Spec.KProbes).To(HaveLen(1))
			Expect(tracingpolicy.Spec.KProbes[0].Message).To(Equal("[10] TEST_RULE"))
			Expect(tracingpolicy.Spec.KProbes[0].Tags).To(Equal([]string{"tag"}))

		})
		It("should generate Tetragon TracingPolicy correctly", func() {
			By("calling GenerateKProbeEnforcePolicy")
			tcs := []struct {
				Name     string
				Policy   securityv1alpha1.WorkloadSecurityPolicy
				Expected tragonv1alpha1.KProbeSpec
			}{
				{
					Name: "Test protect mode",
					Policy: securityv1alpha1.WorkloadSecurityPolicy{
						Spec: securityv1alpha1.WorkloadSecurityPolicySpec{
							Mode:     securityv1alpha1.ProtectMode,
							Selector: &metav1.LabelSelector{},
							Rules: securityv1alpha1.WorkloadSecurityPolicyRules{
								Executables: securityv1alpha1.WorkloadSecurityPolicyExecutables{
									Allowed: []string{
										"/usr/bin/sleep",
									},
									AllowedPrefixes: []string{},
								},
							},
							Severity: 0,
							Tags:     []string{},
							Message:  "",
						},
					},
					Expected: tragonv1alpha1.KProbeSpec{
						Call:    "security_bprm_creds_for_exec",
						Syscall: false,
						Args: []tragonv1alpha1.KProbeArg{
							{
								Index: 0,
								Type:  "linux_binprm",
							},
						},
						Selectors: []tragonv1alpha1.KProbeSelector{
							{
								MatchArgs: []tragonv1alpha1.ArgSelector{
									{
										Index:    0,
										Operator: "NotEqual",
										Values:   []string{"/usr/bin/sleep"},
									},
								},
								MatchActions: []tragonv1alpha1.ActionSelector{
									{
										Action:   "Override",
										ArgError: -1,
									},
								},
							},
						},
						Message: "[0] ",
						Tags:    []string{},
					},
				},
				{
					Name: "Test monitor mode",
					Policy: securityv1alpha1.WorkloadSecurityPolicy{
						Spec: securityv1alpha1.WorkloadSecurityPolicySpec{
							Mode:     securityv1alpha1.MonitorMode,
							Selector: &metav1.LabelSelector{},
							Rules: securityv1alpha1.WorkloadSecurityPolicyRules{
								Executables: securityv1alpha1.WorkloadSecurityPolicyExecutables{
									Allowed: []string{
										"/usr/bin/sleep",
									},
									AllowedPrefixes: []string{},
								},
							},
							Severity: 0,
							Tags:     []string{},
							Message:  "",
						},
					},
					Expected: tragonv1alpha1.KProbeSpec{
						Call:    "security_bprm_creds_for_exec",
						Syscall: false,
						Args: []tragonv1alpha1.KProbeArg{
							{
								Index: 0,
								Type:  "linux_binprm",
							},
						},
						Selectors: []tragonv1alpha1.KProbeSelector{
							{
								MatchArgs: []tragonv1alpha1.ArgSelector{
									{
										Index:    0,
										Operator: "NotEqual",
										Values:   []string{"/usr/bin/sleep"},
									},
								},
							},
						},
						Message: "[0] ",
						Tags:    []string{},
					},
				},
			}

			for _, tc := range tcs {
				log := log.FromContext(ctx)
				log.Info(tc.Name)
				tetragonPolicySpec := tc.Policy.Spec.IntoTetragonPolicySpec()
				Expect(tetragonPolicySpec.KProbes[0]).To(Equal(tc.Expected))
			}

		})
	})

	Context("When deleting a resource", func() {
		It("should not delete if pods are using the policy", func() {
			const resourceName = "test-deletion-with-pods"
			typeNamespacedName := types.NamespacedName{
				Name:      resourceName,
				Namespace: "default",
			}

			By("creating a policy with selector and finalizer")
			policy := &securityv1alpha1.WorkloadSecurityPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:       resourceName,
					Namespace:  "default",
					Finalizers: []string{controller.WorkloadSecurityPolicyFinalizer},
				},
				Spec: securityv1alpha1.WorkloadSecurityPolicySpec{
					Mode: securityv1alpha1.MonitorMode,
					Selector: &metav1.LabelSelector{
						MatchLabels: map[string]string{
							"app": "test-deletion",
						},
					},
					Rules: securityv1alpha1.WorkloadSecurityPolicyRules{
						Executables: securityv1alpha1.WorkloadSecurityPolicyExecutables{
							Allowed: []string{"/usr/bin/sleep"},
						},
					},
					Severity: 10,
					Tags:     []string{},
					Message:  "",
				},
			}
			Expect(k8sClient.Create(ctx, policy)).To(Succeed())

			By("creating a pod matching the selector")
			pod := &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-pod-deletion",
					Namespace: "default",
					Labels: map[string]string{
						"app": "test-deletion",
					},
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:  "test",
							Image: "nginx:latest",
						},
					},
					RestartPolicy: corev1.RestartPolicyNever,
				},
			}
			Expect(k8sClient.Create(ctx, pod)).To(Succeed())

			By("deleting the policy (which sets deletion timestamp)")
			Expect(k8sClient.Delete(ctx, policy)).To(Succeed())

			By("reconciling should not remove finalizer")
			controllerReconciler := &controller.WorkloadSecurityPolicyReconciler{
				Client: k8sClient,
				Scheme: k8sClient.Scheme(),
			}

			_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})
			Expect(err).NotTo(HaveOccurred())

			By("verifying finalizer is still present")
			updatedPolicy := &securityv1alpha1.WorkloadSecurityPolicy{}
			Expect(k8sClient.Get(ctx, typeNamespacedName, updatedPolicy)).To(Succeed())
			Expect(controllerutil.ContainsFinalizer(
				updatedPolicy,
				controller.WorkloadSecurityPolicyFinalizer,
			)).To(BeTrue())

			By("cleaning up pod")
			Expect(k8sClient.Delete(ctx, pod)).To(Succeed())

			By("waiting for pod to be deleted")
			Eventually(func() bool {
				getErr := k8sClient.Get(ctx, types.NamespacedName{Name: pod.Name, Namespace: pod.Namespace}, pod)
				return errors.IsNotFound(getErr)
			}).Should(BeTrue())

			By("reconciling again to remove finalizer now that pod is gone")
			_, err = controllerReconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})
			Expect(err).NotTo(HaveOccurred())

			By("verifying policy is deleted")
			Eventually(func() bool {
				getErr := k8sClient.Get(ctx, typeNamespacedName, updatedPolicy)
				return errors.IsNotFound(getErr)
			}).Should(BeTrue())
		})

		It("should delete Tetragon policy and remove finalizer when no pods exist", func() {
			const resourceName = "test-deletion-no-pods"
			typeNamespacedName := types.NamespacedName{
				Name:      resourceName,
				Namespace: "default",
			}

			By("creating a policy with selector and finalizer")
			policy := &securityv1alpha1.WorkloadSecurityPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:       resourceName,
					Namespace:  "default",
					Finalizers: []string{controller.WorkloadSecurityPolicyFinalizer},
				},
				Spec: securityv1alpha1.WorkloadSecurityPolicySpec{
					Mode: securityv1alpha1.MonitorMode,
					Selector: &metav1.LabelSelector{
						MatchLabels: map[string]string{
							"app": "test-deletion-no-pods",
						},
					},
					Rules: securityv1alpha1.WorkloadSecurityPolicyRules{
						Executables: securityv1alpha1.WorkloadSecurityPolicyExecutables{
							Allowed: []string{"/usr/bin/sleep"},
						},
					},
					Severity: 10,
					Tags:     []string{},
					Message:  "",
				},
			}
			Expect(k8sClient.Create(ctx, policy)).To(Succeed())

			By("creating Tetragon policy")
			tetragonPolicy := &tragonv1alpha1.TracingPolicyNamespaced{
				ObjectMeta: metav1.ObjectMeta{
					Name:      resourceName,
					Namespace: "default",
				},
				Spec: tragonv1alpha1.TracingPolicySpec{
					KProbes: []tragonv1alpha1.KProbeSpec{
						{
							Call:    "security_bprm_creds_for_exec",
							Syscall: false,
						},
					},
				},
			}
			Expect(k8sClient.Create(ctx, tetragonPolicy)).To(Succeed())

			By("deleting the policy (which sets deletion timestamp)")
			Expect(k8sClient.Delete(ctx, policy)).To(Succeed())

			By("reconciling should remove finalizer and delete Tetragon policy")
			controllerReconciler := &controller.WorkloadSecurityPolicyReconciler{
				Client: k8sClient,
				Scheme: k8sClient.Scheme(),
			}

			_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})
			Expect(err).NotTo(HaveOccurred())

			By("verifying Tetragon policy is deleted")
			deletedTetragonPolicy := &tragonv1alpha1.TracingPolicyNamespaced{}
			getErr := k8sClient.Get(ctx, typeNamespacedName, deletedTetragonPolicy)
			Expect(errors.IsNotFound(getErr)).To(BeTrue())

			By("verifying finalizer is removed and policy is deleted")
			updatedPolicy := &securityv1alpha1.WorkloadSecurityPolicy{}
			Eventually(func() bool {
				checkErr := k8sClient.Get(ctx, typeNamespacedName, updatedPolicy)
				return errors.IsNotFound(checkErr)
			}).Should(BeTrue())
		})

		It("should ignore pods with deletion timestamp", func() {
			const resourceName = "test-deletion-pods-deleting"
			typeNamespacedName := types.NamespacedName{
				Name:      resourceName,
				Namespace: "default",
			}

			By("creating a policy with selector and finalizer")
			policy := &securityv1alpha1.WorkloadSecurityPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:       resourceName,
					Namespace:  "default",
					Finalizers: []string{controller.WorkloadSecurityPolicyFinalizer},
				},
				Spec: securityv1alpha1.WorkloadSecurityPolicySpec{
					Mode: securityv1alpha1.MonitorMode,
					Selector: &metav1.LabelSelector{
						MatchLabels: map[string]string{
							"app": "test-deletion-pods-deleting",
						},
					},
					Rules: securityv1alpha1.WorkloadSecurityPolicyRules{
						Executables: securityv1alpha1.WorkloadSecurityPolicyExecutables{
							Allowed: []string{"/usr/bin/sleep"},
						},
					},
					Severity: 10,
					Tags:     []string{},
					Message:  "",
				},
			}
			Expect(k8sClient.Create(ctx, policy)).To(Succeed())

			By("creating a pod matching the selector")
			pod := &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-pod-deleting",
					Namespace: "default",
					Labels: map[string]string{
						"app": "test-deletion-pods-deleting",
					},
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:  "test",
							Image: "nginx:latest",
						},
					},
					RestartPolicy: corev1.RestartPolicyNever,
				},
			}
			Expect(k8sClient.Create(ctx, pod)).To(Succeed())

			By("deleting the pod (which sets deletion timestamp)")
			Expect(k8sClient.Delete(ctx, pod)).To(Succeed())

			By("deleting the policy (which sets deletion timestamp)")
			Expect(k8sClient.Delete(ctx, policy)).To(Succeed())

			By("reconciling should proceed with deletion since pod is being deleted")
			controllerReconciler := &controller.WorkloadSecurityPolicyReconciler{
				Client: k8sClient,
				Scheme: k8sClient.Scheme(),
			}

			_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})
			Expect(err).NotTo(HaveOccurred())

			By("verifying finalizer is removed and policy is deleted")
			updatedPolicy := &securityv1alpha1.WorkloadSecurityPolicy{}
			Eventually(func() bool {
				getErr := k8sClient.Get(ctx, typeNamespacedName, updatedPolicy)
				return errors.IsNotFound(getErr)
			}).Should(BeTrue())
		})

		It("should allow deletion when policy has no selector", func() {
			const resourceName = "test-deletion-no-selector"
			typeNamespacedName := types.NamespacedName{
				Name:      resourceName,
				Namespace: "default",
			}

			By("creating a policy without selector and with finalizer")
			policy := &securityv1alpha1.WorkloadSecurityPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:       resourceName,
					Namespace:  "default",
					Finalizers: []string{controller.WorkloadSecurityPolicyFinalizer},
				},
				Spec: securityv1alpha1.WorkloadSecurityPolicySpec{
					Mode: securityv1alpha1.MonitorMode,
					Rules: securityv1alpha1.WorkloadSecurityPolicyRules{
						Executables: securityv1alpha1.WorkloadSecurityPolicyExecutables{
							Allowed: []string{"/usr/bin/sleep"},
						},
					},
					Severity: 10,
					Tags:     []string{},
					Message:  "",
				},
			}
			Expect(k8sClient.Create(ctx, policy)).To(Succeed())

			By("deleting the policy (which sets deletion timestamp)")
			Expect(k8sClient.Delete(ctx, policy)).To(Succeed())

			By("reconciling should proceed with deletion")
			controllerReconciler := &controller.WorkloadSecurityPolicyReconciler{
				Client: k8sClient,
				Scheme: k8sClient.Scheme(),
			}

			_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})
			Expect(err).NotTo(HaveOccurred())

			By("verifying finalizer is removed and policy is deleted")
			updatedPolicy := &securityv1alpha1.WorkloadSecurityPolicy{}
			Eventually(func() bool {
				getErr := k8sClient.Get(ctx, typeNamespacedName, updatedPolicy)
				return errors.IsNotFound(getErr)
			}).Should(BeTrue())
		})

		It("should handle deletion when finalizer is already removed", func() {
			const resourceName = "test-deletion-no-finalizer"
			typeNamespacedName := types.NamespacedName{
				Name:      resourceName,
				Namespace: "default",
			}

			By("creating a policy without finalizer")
			policy := &securityv1alpha1.WorkloadSecurityPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      resourceName,
					Namespace: "default",
				},
				Spec: securityv1alpha1.WorkloadSecurityPolicySpec{
					Mode: securityv1alpha1.MonitorMode,
					Rules: securityv1alpha1.WorkloadSecurityPolicyRules{
						Executables: securityv1alpha1.WorkloadSecurityPolicyExecutables{
							Allowed: []string{"/usr/bin/sleep"},
						},
					},
					Severity: 10,
					Tags:     []string{},
					Message:  "",
				},
			}
			Expect(k8sClient.Create(ctx, policy)).To(Succeed())

			By("deleting the policy (which sets deletion timestamp)")
			Expect(k8sClient.Delete(ctx, policy)).To(Succeed())

			By("reconciling should handle gracefully")
			controllerReconciler := &controller.WorkloadSecurityPolicyReconciler{
				Client: k8sClient,
				Scheme: k8sClient.Scheme(),
			}

			_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})
			Expect(err).NotTo(HaveOccurred())

			By("verifying policy is deleted")
			Eventually(func() bool {
				getErr := k8sClient.Get(ctx, typeNamespacedName, policy)
				return errors.IsNotFound(getErr)
			}).Should(BeTrue())
		})
	})
})
