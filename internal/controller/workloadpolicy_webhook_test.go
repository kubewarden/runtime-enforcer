package controller_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/kubewarden/runtime-enforcer/api/v1alpha1"
	"github.com/kubewarden/runtime-enforcer/internal/controller"
	"github.com/kubewarden/runtime-enforcer/internal/types/policymode"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

var _ = Describe("WorkloadPolicy Webhook", func() {
	const (
		testNS        = "default"
		policyName    = "test-policy"
		containerName = "test-container"
		podName       = "test-pod"
	)

	var (
		policy    *v1alpha1.WorkloadPolicy
		validator *controller.PolicyCustomValidator
	)

	BeforeEach(func() {
		policy = &v1alpha1.WorkloadPolicy{
			Name:      policyName,
			Namespace: testNS,
			Spec: v1alpha1.WorkloadPolicySpec{
				Mode: policymode.MonitorString,
				RulesByContainer: map[string]*v1alpha1.WorkloadPolicyRules{
					containerName: {
						Executables: v1alpha1.WorkloadPolicyExecutables{
							Allowed: []string{"/usr/bin/sleep"},
						},
					},
				},
			},
		}
		Expect(k8sClient.Create(ctx, policy)).To(Succeed())

		validator = &controller.PolicyCustomValidator{
			Client: k8sClient,
		}
	})

	AfterEach(func() {
		Expect(client.IgnoreNotFound(k8sClient.Delete(ctx, &v1alpha1.WorkloadPolicy{
			Name: policyName, Namespace: testNS,
		}))).To(Succeed())
	})

	Context("ValidateDelete", func() {
		It("allows deletion when no pods reference the policy", func() {
			warns, err := validator.ValidateDelete(ctx, policy)
			Expect(err).NotTo(HaveOccurred())
			Expect(warns).To(BeEmpty())
		})

		It("denies deletion when a pod references the policy", func() {
			pod := &corev1.Pod{
				Name:      podName,
				Namespace: testNS,
				Labels: map[string]string{
					v1alpha1.PolicyLabelKey: policyName,
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{{Name: containerName, Image: "pause"}},
				},
			}
			Expect(k8sClient.Create(ctx, pod)).To(Succeed())
			DeferCleanup(k8sClient.Delete, ctx, pod)

			_, err := validator.ValidateDelete(ctx, policy)
			Expect(err).To(HaveOccurred())
			Expect(apierrors.IsForbidden(err)).To(BeTrue())
			Expect(err.Error()).To(ContainSubstring(pod.Name))
		})
	})
})
