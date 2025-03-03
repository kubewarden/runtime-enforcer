package controller

import (
	"context"
	"fmt"

	appsv1 "k8s.io/api/apps/v1"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
)

// DaemonSetReconciler reconciles a DaemonSet object.
type DaemonSetReconciler struct {
	CommonReconciler
}

// +kubebuilder:rbac:groups=apps,resources=daemonsets,verbs=get;list;watch

func (r *DaemonSetReconciler) Reconcile(
	ctx context.Context,
	req ctrl.Request,
) (ctrl.Result, error) {
	log := log.FromContext(ctx)

	var err error
	var ds appsv1.DaemonSet
	if err = r.Get(ctx, req.NamespacedName, &ds); err != nil && !k8sErrors.IsNotFound(err) {
		return ctrl.Result{}, fmt.Errorf("failed to get resource: %w", err)
	}
	log.Info("daemonset", "resource", req.NamespacedName)

	return r.reconcileWithProposal(ctx, "DaemonSet", &ds)
}

// SetupWithManager sets up the controller with the Manager.
func (r *DaemonSetReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&appsv1.DaemonSet{}).
		WithEventFilter(predicate.GenerationChangedPredicate{}).
		Named("daemonset").
		Complete(r)
}
