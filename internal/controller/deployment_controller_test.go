package controller_test

import (
	"context"

	"github.com/neuvector/runtime-enforcement/internal/controller"
	. "github.com/onsi/ginkgo/v2" //nolint:revive // Required for testing
	. "github.com/onsi/gomega"    //nolint:revive // Required for testing

	appsv1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	securityv1alpha1 "github.com/neuvector/runtime-enforcement/api/v1alpha1"
)

var _ = Describe("Deployment Controller", func() {
	Context("When reconciling a resource", func() {
		It("should successfully reconcile Deployment resource", func() {

			fakeClient := fake.NewClientBuilder().WithScheme(k8sClient.Scheme()).WithObjects(&appsv1.Deployment{
				TypeMeta: metav1.TypeMeta{},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "deployment",
					Namespace: "default",
				},
				Spec: appsv1.DeploymentSpec{
					Selector: &metav1.LabelSelector{},
				},
				Status: appsv1.DeploymentStatus{},
			}).Build()

			deploymentReconciler := &controller.DeploymentReconciler{
				CommonReconciler: controller.CommonReconciler{
					Client: fakeClient,
					Scheme: k8sClient.Scheme(),
				},
			}

			req := reconcile.Request{
				NamespacedName: types.NamespacedName{
					Name:      "deployment",
					Namespace: "default",
				},
			}

			_, err := deploymentReconciler.Reconcile(context.Background(), req)
			Expect(err).NotTo(HaveOccurred())

			var proposal securityv1alpha1.WorkloadSecurityPolicyProposal
			err = fakeClient.Get(context.Background(), types.NamespacedName{
				Name:      "deploy-deployment",
				Namespace: "default",
			}, &proposal)
			Expect(err).NotTo(HaveOccurred())

		})
	})
})
