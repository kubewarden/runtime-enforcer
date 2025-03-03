package controller_test

import (
	"context"

	securityv1alpha1 "github.com/neuvector/runtime-enforcement/api/v1alpha1"
	"github.com/neuvector/runtime-enforcement/internal/controller"

	. "github.com/onsi/ginkgo/v2" //nolint:revive // Required for testing
	. "github.com/onsi/gomega"    //nolint:revive // Required for testing

	appsv1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

var _ = Describe("StatefulSet Controller", func() {
	Context("When reconciling a resource", func() {
		It("should successfully reconcile resource", func() {

			fakeClient := fake.NewClientBuilder().WithScheme(k8sClient.Scheme()).WithObjects(&appsv1.StatefulSet{
				TypeMeta: metav1.TypeMeta{},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "statefulset",
					Namespace: "default",
				},
				Spec: appsv1.StatefulSetSpec{
					Selector: &metav1.LabelSelector{
						MatchLabels: map[string]string{
							"app": "statefulset",
						},
					},
				},
				Status: appsv1.StatefulSetStatus{},
			}).Build()

			stsReconciler := &controller.StatefulSetReconciler{
				CommonReconciler: controller.CommonReconciler{
					Client: fakeClient,
					Scheme: k8sClient.Scheme(),
				},
			}

			req := reconcile.Request{
				NamespacedName: types.NamespacedName{
					Name:      "statefulset",
					Namespace: "default",
				},
			}

			_, err := stsReconciler.Reconcile(context.Background(), req)
			Expect(err).NotTo(HaveOccurred())

			var proposal securityv1alpha1.WorkloadSecurityPolicyProposal
			err = fakeClient.Get(context.Background(), types.NamespacedName{
				Name:      "sts-statefulset",
				Namespace: "default",
			}, &proposal)
			Expect(err).NotTo(HaveOccurred())

			Expect(proposal.Name).To(Equal("sts-statefulset"))
			Expect(proposal.Namespace).To(Equal("default"))
			Expect(len(proposal.OwnerReferences)).To(Equal(1))
			Expect(proposal.OwnerReferences[0].Kind).To(Equal("StatefulSet"))
			Expect(proposal.OwnerReferences[0].Name).To(Equal("statefulset"))
			Expect(proposal.Spec.Selector).To(Equal(&metav1.LabelSelector{
				MatchLabels: map[string]string{
					"app": "statefulset",
				},
			}))
		})
	})
	It("should handle conflict correctly", func() {
		fakeClient := fake.NewClientBuilder().WithScheme(k8sClient.Scheme()).WithObjects(
			&appsv1.StatefulSet{
				TypeMeta: metav1.TypeMeta{},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "statefulset",
					Namespace: "default",
				},
				Spec: appsv1.StatefulSetSpec{
					Selector: &metav1.LabelSelector{
						MatchLabels: map[string]string{
							"app": "statefulset",
						},
					},
				},
				Status: appsv1.StatefulSetStatus{},
			},
			&securityv1alpha1.WorkloadSecurityPolicyProposal{
				TypeMeta: metav1.TypeMeta{},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "sts-statefulset",
					Namespace: "default",
				},
			}).Build()

		conflictClient := ConflictFakeClient{
			Client: fakeClient,
		}

		stsReconciler := &controller.StatefulSetReconciler{
			CommonReconciler: controller.CommonReconciler{
				Client: conflictClient,
				Scheme: k8sClient.Scheme(),
			},
		}

		req := reconcile.Request{
			NamespacedName: types.NamespacedName{
				Name:      "statefulset",
				Namespace: "default",
			},
		}

		_, err := stsReconciler.Reconcile(context.Background(), req)
		Expect(err).NotTo(HaveOccurred())

		var proposal securityv1alpha1.WorkloadSecurityPolicyProposal
		err = fakeClient.Get(context.Background(), types.NamespacedName{
			Name:      "sts-statefulset",
			Namespace: "default",
		}, &proposal)
		Expect(err).NotTo(HaveOccurred())

		Expect(proposal.Name).To(Equal("sts-statefulset"))
		Expect(proposal.Namespace).To(Equal("default"))
		Expect(len(proposal.OwnerReferences)).To(Equal(1))
		Expect(proposal.OwnerReferences[0].Kind).To(Equal("StatefulSet"))
		Expect(proposal.OwnerReferences[0].Name).To(Equal("statefulset"))
		Expect(proposal.Spec.Selector).To(Equal(&metav1.LabelSelector{
			MatchLabels: map[string]string{
				"app": "statefulset",
			},
		}))
	})
})
