package controller_test

import (
	. "github.com/onsi/ginkgo/v2" //nolint:revive // Required for testing
	. "github.com/onsi/gomega"    //nolint:revive // Required for testing

	securityv1alpha1 "github.com/neuvector/runtime-enforcement/api/v1alpha1"
	"github.com/neuvector/runtime-enforcement/internal/controller"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
)

var _ = Describe("WorkloadSecurityPolicyProposal Webhook", func() {
	Context("When learning a process", func() {
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

		It("should successfully handle webhook request", func() {
			By("injecting the owner refernces and selector correctly")

			tcs := []struct {
				Resource *securityv1alpha1.WorkloadSecurityPolicyProposal
				Expected *securityv1alpha1.WorkloadSecurityPolicyProposal
				Success  bool
			}{
				{
					Resource: &securityv1alpha1.WorkloadSecurityPolicyProposal{
						ObjectMeta: metav1.ObjectMeta{
							Name:      "deploy-ubuntu-deployment",
							Namespace: "default",
							OwnerReferences: []metav1.OwnerReference{
								{
									Kind: "Deployment",
									Name: "ubuntu-deployment",
								},
							},
						},
						Spec: securityv1alpha1.WorkloadSecurityPolicyProposalSpec{},
					},
					Expected: &securityv1alpha1.WorkloadSecurityPolicyProposal{
						ObjectMeta: metav1.ObjectMeta{
							Name:      "deploy-ubuntu-deployment",
							Namespace: "default",
							OwnerReferences: []metav1.OwnerReference{
								{
									Kind:               "Deployment",
									Name:               "ubuntu-deployment",
									APIVersion:         "apps/v1",
									Controller:         ptr.To(true),
									BlockOwnerDeletion: ptr.To(true),
								},
							},
						},
						Spec: securityv1alpha1.WorkloadSecurityPolicyProposalSpec{
							Selector: &metav1.LabelSelector{
								MatchLabels: map[string]string{
									"app": "ubuntu",
								},
							},
						},
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
})
