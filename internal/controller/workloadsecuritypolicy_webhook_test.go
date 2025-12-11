package controller_test

import (
	. "github.com/onsi/ginkgo/v2" //nolint:revive // Required for testing
	. "github.com/onsi/gomega"    //nolint:revive // Required for testing

	securityv1alpha1 "github.com/neuvector/runtime-enforcer/api/v1alpha1"
	"github.com/neuvector/runtime-enforcer/internal/controller"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

var _ = Describe("WorkloadSecurityPolicy Webhook", func() {
	Context("When creating a WorkloadSecurityPolicy", func() {
		It("should add finalizer on CREATE", func() {
			By("creating a policy without finalizer")

			policy := &securityv1alpha1.WorkloadSecurityPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-policy",
					Namespace: "default",
				},
				Spec: securityv1alpha1.WorkloadSecurityPolicySpec{
					Mode: securityv1alpha1.MonitorMode,
					Selector: &metav1.LabelSelector{
						MatchLabels: map[string]string{
							"app": "test",
						},
					},
					Rules: securityv1alpha1.WorkloadSecurityPolicyRules{
						Executables: securityv1alpha1.WorkloadSecurityPolicyExecutables{
							Allowed: []string{
								"/usr/bin/sleep",
							},
						},
					},
				},
			}

			webhook := &controller.PolicyWebhook{}
			err := webhook.Default(ctx, policy)
			Expect(err).NotTo(HaveOccurred())
			Expect(controllerutil.ContainsFinalizer(policy, controller.WorkloadSecurityPolicyFinalizer)).To(BeTrue())
			Expect(policy.Finalizers).To(ContainElement(controller.WorkloadSecurityPolicyFinalizer))
		})

		It("should be idempotent - not add duplicate finalizer", func() {
			By("creating a policy with finalizer already present")

			policy := &securityv1alpha1.WorkloadSecurityPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:       "test-policy-idempotent",
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
				},
			}

			initialFinalizerCount := len(policy.Finalizers)

			webhook := &controller.PolicyWebhook{}
			err := webhook.Default(ctx, policy)
			Expect(err).NotTo(HaveOccurred())
			Expect(policy.Finalizers).To(HaveLen(initialFinalizerCount))
			Expect(policy.Finalizers).To(ContainElement(controller.WorkloadSecurityPolicyFinalizer))
		})

		It("should add finalizer even when other finalizers exist", func() {
			By("creating a policy with other finalizers")

			policy := &securityv1alpha1.WorkloadSecurityPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:       "test-policy-multiple-finalizers",
					Namespace:  "default",
					Finalizers: []string{"other-finalizer"},
				},
				Spec: securityv1alpha1.WorkloadSecurityPolicySpec{
					Mode: securityv1alpha1.ProtectMode,
					Rules: securityv1alpha1.WorkloadSecurityPolicyRules{
						Executables: securityv1alpha1.WorkloadSecurityPolicyExecutables{
							AllowedPrefixes: []string{"/bin/"},
						},
					},
				},
			}

			webhook := &controller.PolicyWebhook{}
			err := webhook.Default(ctx, policy)
			Expect(err).NotTo(HaveOccurred())
			Expect(policy.Finalizers).To(ContainElement("other-finalizer"))
			Expect(policy.Finalizers).To(ContainElement(controller.WorkloadSecurityPolicyFinalizer))
			Expect(policy.Finalizers).To(HaveLen(2))
		})

		It("should return error for wrong object type", func() {
			By("passing wrong object type to webhook")

			wrongObject := &securityv1alpha1.WorkloadSecurityPolicyProposal{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "wrong-type",
					Namespace: "default",
				},
			}

			webhook := &controller.PolicyWebhook{}
			err := webhook.Default(ctx, wrongObject)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("expected a WorkloadSecurityPolicy"))
		})
	})
})
