package controller

import (
	"context"
	"fmt"

	appsv1 "k8s.io/api/apps/v1"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

// StatefulSetReconciler reconciles a StatefulSet object.
type StatefulSetReconciler struct {
	CommonReconciler
}

// +kubebuilder:rbac:groups=apps,resources=statefulsets,verbs=get;list;watch

func (r *StatefulSetReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := log.FromContext(ctx)

	var err error
	var sts appsv1.StatefulSet
	if err = r.Get(ctx, req.NamespacedName, &sts); err != nil && !k8sErrors.IsNotFound(err) {
		return ctrl.Result{}, fmt.Errorf("failed to get resource: %w", err)
	}
	log.Info("replicaset", "resource", req.NamespacedName)

	return r.reconcileWithProposal(ctx, "StatefulSet", &sts)
}

// SetupWithManager sets up the controller with the Manager.
func (r *StatefulSetReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&appsv1.StatefulSet{}).
		Named("statefulset").
		Complete(r)
}
