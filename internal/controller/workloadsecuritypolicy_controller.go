package controller

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"

	tetragonv1alpha1 "github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	securityv1alpha1 "github.com/neuvector/runtime-enforcement/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// WorkloadSecurityPolicyReconciler reconciles a WorkloadSecurityPolicy object.
type WorkloadSecurityPolicyReconciler struct {
	client.Client

	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=security.rancher.io,resources=workloadsecuritypolicies,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=security.rancher.io,resources=workloadsecuritypolicies/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=security.rancher.io,resources=workloadsecuritypolicies/finalizers,verbs=update
// +kubebuilder:rbac:groups=cilium.io,resources=tracingpoliciesnamespaced,verbs=get;list;watch;create;update;patch;delete

func (r *WorkloadSecurityPolicyReconciler) Reconcile(
	ctx context.Context,
	req ctrl.Request,
) (ctrl.Result, error) {
	log := log.FromContext(ctx)

	log.Info("workloadsecuritypolicy", "req", req)

	var policy securityv1alpha1.WorkloadSecurityPolicy
	var err error
	if err = r.Get(ctx, req.NamespacedName, &policy); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	if policy.GetDeletionTimestamp() != nil {
		return ctrl.Result{}, nil
	}

	tetragonPolicy := tetragonv1alpha1.TracingPolicyNamespaced{
		ObjectMeta: metav1.ObjectMeta{
			Name:      policy.Name,
			Namespace: policy.Namespace,
		},
	}

	_, err = controllerutil.CreateOrPatch(ctx, r.Client, &tetragonPolicy, func() error {
		tetragonPolicy.Spec = policy.Spec.IntoTetragonPolicySpec()
		err = controllerutil.SetControllerReference(&policy, &tetragonPolicy, r.Scheme)
		if err != nil {
			return fmt.Errorf("failed to set controller reference: %w", err)
		}
		return nil
	})
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to call CreateOrPatch: %w", err)
	}

	return ctrl.Result{}, r.updateStatus(ctx, &policy)
}

func (r *WorkloadSecurityPolicyReconciler) updateStatus(
	ctx context.Context,
	policy *securityv1alpha1.WorkloadSecurityPolicy,
) error {
	newPolicy := policy.DeepCopy()
	newPolicy.Status.ObservedGeneration = newPolicy.Generation
	newPolicy.Status.State = securityv1alpha1.DeployedState
	return r.Status().Update(ctx, newPolicy)
}

// SetupWithManager sets up the controller with the Manager.
func (r *WorkloadSecurityPolicyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if err := tetragonv1alpha1.AddToScheme(mgr.GetScheme()); err != nil {
		return err
	}
	return ctrl.NewControllerManagedBy(mgr).
		For(&securityv1alpha1.WorkloadSecurityPolicy{}).
		Named("workloadsecuritypolicy").
		Complete(r)
}
