package controller

import (
	"context"
	"fmt"

	batchv1 "k8s.io/api/batch/v1"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

// CronJobReconciler reconciles a CronJob object.
type CronJobReconciler struct {
	CommonReconciler
}

// +kubebuilder:rbac:groups=batch,resources=cronjobs,verbs=get;list;watch

func (r *CronJobReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := log.FromContext(ctx)

	var err error
	var cronjob batchv1.CronJob
	if err = r.Get(ctx, req.NamespacedName, &cronjob); err != nil && !k8sErrors.IsNotFound(err) {
		return ctrl.Result{}, fmt.Errorf("failed to get resource: %w", err)
	}
	log.Info("job", "resource", req.NamespacedName)

	return r.reconcileWithProposal(ctx, "CronJob", &cronjob)
}

// SetupWithManager sets up the controller with the Manager.
func (r *CronJobReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&batchv1.CronJob{}).
		Named("cronjob").
		Complete(r)
}
