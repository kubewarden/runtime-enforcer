package controller_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	securityv1alpha1 "github.com/kubewarden/runtime-enforcer/api/v1alpha1"
	"github.com/kubewarden/runtime-enforcer/internal/controller"
	"github.com/kubewarden/runtime-enforcer/internal/types/policymode"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

var _ = Describe("WorkloadPolicyProposal Webhook", func() {
	Context("When learning a process", func() {
		typeNamespacedName := types.NamespacedName{
			Name:      "opensuse-deployment",
			Namespace: "default",
		}

		proposal := &securityv1alpha1.WorkloadPolicyProposal{
			Name:      "deploy-opensuse-deployment",
			Namespace: "default",
			Spec:      securityv1alpha1.WorkloadPolicyProposalSpec{},
		}

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

		It("should successfully handle webhook request", func() {
			By("injecting the owner refernces and selector correctly")

			tcs := []struct {
				Resource *securityv1alpha1.WorkloadPolicyProposal
				Expected *securityv1alpha1.WorkloadPolicyProposal
				Success  bool
			}{
				{
					Resource: &securityv1alpha1.WorkloadPolicyProposal{
						Name:      "deploy-opensuse-deployment",
						Namespace: "default",
						OwnerReferences: []metav1.OwnerReference{
							{
								Kind: "Deployment",
								Name: "opensuse-deployment",
							},
						},
						Spec: securityv1alpha1.WorkloadPolicyProposalSpec{},
					},
					Expected: &securityv1alpha1.WorkloadPolicyProposal{
						Name:      "deploy-opensuse-deployment",
						Namespace: "default",
						OwnerReferences: []metav1.OwnerReference{
							{
								Kind:               "Deployment",
								Name:               "opensuse-deployment",
								APIVersion:         "apps/v1",
								Controller:         new(true),
								BlockOwnerDeletion: new(true),
							},
						},
						Spec: securityv1alpha1.WorkloadPolicyProposalSpec{},
					},
					Success: true,
				},
			}

			policyWebhook := &controller.ProposalWebhook{
				Client: k8sClient,
			}

			for _, tc := range tcs {
				if tc.Success {
					Expect(policyWebhook.Default(ctx, tc.Resource)).To(Succeed())
					tc.Resource.OwnerReferences[0].UID = ""
					Expect(tc.Resource).To(Equal(tc.Expected))
				} else {
					err := policyWebhook.Default(ctx, tc.Resource)
					Expect(err).To(HaveOccurred())
				}
			}
		})
	})

	Context("ValidatePromotionLabel", func() {
		var webhook *controller.ProposalWebhook

		BeforeEach(func() {
			webhook = &controller.ProposalWebhook{}
		})

		It("allows create without promote label", func() {
			proposal := &securityv1alpha1.WorkloadPolicyProposal{
				Name: "test-proposal",
			}
			warns, err := webhook.ValidateCreate(ctx, proposal)
			Expect(err).NotTo(HaveOccurred())
			Expect(warns).To(BeEmpty())
		})

		It("allows create with monitor promote label", func() {
			proposal := &securityv1alpha1.WorkloadPolicyProposal{
				Name: "test-proposal",
				Labels: map[string]string{
					securityv1alpha1.ProposalPromoteLabelKey: policymode.MonitorString,
				},
			}
			warns, err := webhook.ValidateCreate(ctx, proposal)
			Expect(err).NotTo(HaveOccurred())
			Expect(warns).To(BeEmpty())
		})

		It("allows update with protect promote label", func() {
			proposal := &securityv1alpha1.WorkloadPolicyProposal{
				Name: "test-proposal",
				Labels: map[string]string{
					securityv1alpha1.ProposalPromoteLabelKey: policymode.ProtectString,
				},
			}
			warns, err := webhook.ValidateUpdate(ctx, proposal, proposal)
			Expect(err).NotTo(HaveOccurred())
			Expect(warns).To(BeEmpty())
		})

		It("denies create with unsupported promote label", func() {
			proposal := &securityv1alpha1.WorkloadPolicyProposal{
				Name: "test-proposal",
				Labels: map[string]string{
					securityv1alpha1.ProposalPromoteLabelKey: "true",
				},
			}
			warns, err := webhook.ValidateCreate(ctx, proposal)
			Expect(err).To(HaveOccurred())
			Expect(apierrors.IsInvalid(err)).To(BeTrue())
			Expect(err.Error()).To(ContainSubstring(`unsupported value "true"`))
			Expect(warns).To(BeEmpty())
		})
	})
})
