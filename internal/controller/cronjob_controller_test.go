package controller_test

import (
	"context"

	securityv1alpha1 "github.com/neuvector/runtime-enforcement/api/v1alpha1"
	"github.com/neuvector/runtime-enforcement/internal/controller"
	. "github.com/onsi/ginkgo/v2" //nolint:revive // Required for testing
	. "github.com/onsi/gomega"    //nolint:revive // Required for testing
	batchv1 "k8s.io/api/batch/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

var _ = Describe("CronJob Controller", func() {
	Context("When reconciling a resource", func() {
		It("should successfully reconcile resource", func() {

			fakeClient := fake.NewClientBuilder().WithScheme(k8sClient.Scheme()).WithObjects(&batchv1.CronJob{
				TypeMeta: metav1.TypeMeta{},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "cronjob",
					Namespace: "default",
					UID:       "00000000-0000-0000-0000-0123456789ab",
				},
				Spec: batchv1.CronJobSpec{
					JobTemplate: batchv1.JobTemplateSpec{
						Spec: batchv1.JobSpec{
							Selector: &metav1.LabelSelector{
								MatchLabels: map[string]string{
									"app": "cronjob",
								},
							},
						},
					},
				},
				Status: batchv1.CronJobStatus{},
			}).Build()

			cronjobReconciler := &controller.CronJobReconciler{
				CommonReconciler: controller.CommonReconciler{
					Client: fakeClient,
					Scheme: k8sClient.Scheme(),
				},
			}

			req := reconcile.Request{
				NamespacedName: types.NamespacedName{
					Name:      "cronjob",
					Namespace: "default",
				},
			}

			_, err := cronjobReconciler.Reconcile(context.Background(), req)
			Expect(err).NotTo(HaveOccurred())

			var proposal securityv1alpha1.WorkloadSecurityPolicyProposal
			err = fakeClient.Get(context.Background(), types.NamespacedName{
				Name:      "cronjob-cronjob",
				Namespace: "default",
			}, &proposal)
			Expect(err).NotTo(HaveOccurred())

			Expect(proposal.Name).To(Equal("cronjob-cronjob"))
			Expect(proposal.Namespace).To(Equal("default"))
			Expect(len(proposal.OwnerReferences)).To(Equal(1))
			Expect(proposal.OwnerReferences[0].Kind).To(Equal("CronJob"))
			Expect(proposal.OwnerReferences[0].Name).To(Equal("cronjob"))
			Expect(string(proposal.OwnerReferences[0].UID)).To(Equal("00000000-0000-0000-0000-0123456789ab"))
			Expect(proposal.Spec.Selector).To(Equal(&metav1.LabelSelector{
				MatchLabels: map[string]string{
					"app": "cronjob",
				},
			}))
		})
	})
})
