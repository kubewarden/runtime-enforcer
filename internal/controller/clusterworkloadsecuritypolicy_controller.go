package controller

import (
	"context"
	"fmt"

	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/util/retry"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"

	tetragonv1alpha1 "github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	securityv1alpha1 "github.com/neuvector/runtime-enforcement/api/v1alpha1"
)

// ClusterWorkloadSecurityPolicyReconciler reconciles a ClusterWorkloadSecurityPolicy object.
type ClusterWorkloadSecurityPolicyReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=security.rancher.io,resources=clusterworkloadsecuritypolicies,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=security.rancher.io,resources=clusterworkloadsecuritypolicies/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=security.rancher.io,resources=clusterworkloadsecuritypolicies/finalizers,verbs=update

//nolint:dupl // we're more tolerant with controller code.
func (r *ClusterWorkloadSecurityPolicyReconciler) Reconcile(
	ctx context.Context,
	req ctrl.Request,
) (ctrl.Result, error) {
	log := log.FromContext(ctx)

	log.Info("clusterworkloadsecuritypolicy", "req", req)

	var policy securityv1alpha1.ClusterWorkloadSecurityPolicy
	var err error
	if err = r.Get(ctx, req.NamespacedName, &policy); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	var tetragonPolicy tetragonv1alpha1.TracingPolicy
	tetragonPolicy.Name = policy.Name
	tetragonPolicy.Namespace = policy.Namespace
	if err = retry.RetryOnConflict(retry.DefaultBackoff, func() error {
		_, err = controllerutil.CreateOrUpdate(ctx, r.Client, &tetragonPolicy, func() error {
			err = UpdateTetragonPolicy(&policy.Spec, &tetragonPolicy.Spec)
			if err != nil {
				return fmt.Errorf("failed to update Tetragon Policy: %w", err)
			}
			err = controllerutil.SetControllerReference(&policy, &tetragonPolicy, r.Scheme)
			if err != nil {
				return fmt.Errorf("failed to set controller reference: %w", err)
			}
			return nil
		})
		if err != nil {
			return fmt.Errorf("failed to call CreateOrUpdate: %w", err)
		}
		return nil
	}); err != nil {
		return ctrl.Result{}, r.reportError(ctx, &policy, err)
	}

	return ctrl.Result{}, r.updateStatus(ctx, &policy)
}

func (r *ClusterWorkloadSecurityPolicyReconciler) reportError(
	ctx context.Context,
	policy *securityv1alpha1.ClusterWorkloadSecurityPolicy,
	err error,
) error {
	newPolicy := policy.DeepCopy()
	if newPolicy.Status.Conditions == nil {
		newPolicy.Status.Conditions = make([]metav1.Condition, 0)
	}
	apimeta.SetStatusCondition(&newPolicy.Status.Conditions, metav1.Condition{
		Type:               securityv1alpha1.DeployCondition,
		Status:             metav1.ConditionFalse,
		Reason:             securityv1alpha1.SyncFailedReason,
		Message:            err.Error(),
		ObservedGeneration: newPolicy.Status.ObservedGeneration,
	})
	newPolicy.Status.State = securityv1alpha1.ErrorState
	newPolicy.Status.Reason = err.Error()
	return r.Status().Update(ctx, newPolicy)
}

func (r *ClusterWorkloadSecurityPolicyReconciler) updateStatus(
	ctx context.Context,
	policy *securityv1alpha1.ClusterWorkloadSecurityPolicy,
) error {
	newPolicy := policy.DeepCopy()
	newPolicy.Status.ObservedGeneration = newPolicy.Generation
	newPolicy.Status.State = securityv1alpha1.DeployedState
	return r.Status().Update(ctx, newPolicy)
}

// SetupWithManager sets up the controller with the Manager.
func (r *ClusterWorkloadSecurityPolicyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&securityv1alpha1.ClusterWorkloadSecurityPolicy{}).
		Named("clusterworkloadsecuritypolicy").
		Complete(r)
}
