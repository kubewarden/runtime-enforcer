// Package controller provides implementations of kubernetes controllers
//
//nolint:dupl // skip controller implementation
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

// DeploymentReconciler reconciles a Deployment object.
type DeploymentReconciler struct {
	CommonReconciler
}

// +kubebuilder:rbac:groups=apps,resources=deployments,verbs=get;list;watch

func (r *DeploymentReconciler) Reconcile(
	ctx context.Context,
	req ctrl.Request,
) (ctrl.Result, error) {
	log := log.FromContext(ctx)

	var err error
	var deployment appsv1.Deployment
	if err = r.Get(ctx, req.NamespacedName, &deployment); err != nil && !k8sErrors.IsNotFound(err) {
		return ctrl.Result{}, fmt.Errorf("failed to get resource: %w", err)
	}
	log.Info("deployment", "resource", req.NamespacedName)

	return r.reconcileWithProposal(ctx, "Deployment", &deployment)
}

// SetupWithManager sets up the controller with the Manager.
func (r *DeploymentReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if err := ctrl.NewControllerManagedBy(mgr).
		For(&appsv1.Deployment{}).
		Named("deployment").
		WithEventFilter(predicate.GenerationChangedPredicate{}).
		Complete(r); err != nil {
		return fmt.Errorf("failed to create controller: %w", err)
	}
	return nil
}
