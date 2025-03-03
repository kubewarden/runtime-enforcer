package controller

import (
	"context"
	"fmt"

	batchv1 "k8s.io/api/batch/v1"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

// JobReconciler reconciles a Job object.
type JobReconciler struct {
	CommonReconciler
}

// +kubebuilder:rbac:groups=batch,resources=jobs,verbs=get;list;watch

func (r *JobReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := log.FromContext(ctx)

	var err error
	var job batchv1.Job
	if err = r.Get(ctx, req.NamespacedName, &job); err != nil && !k8sErrors.IsNotFound(err) {
		return ctrl.Result{}, fmt.Errorf("failed to get resource: %w", err)
	}
	log.Info("job", "resource", req.NamespacedName)

	return r.reconcileWithProposal(ctx, "Job", &job)
}

// SetupWithManager sets up the controller with the Manager.
func (r *JobReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&batchv1.Job{}).
		Named("job").
		Complete(r)
}
