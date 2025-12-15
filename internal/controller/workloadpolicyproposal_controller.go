package controller

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"

	securityv1alpha1 "github.com/neuvector/runtime-enforcer/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// WorkloadPolicyProposalReconciler reconciles a WorkloadPolicyProposal object.
type WorkloadPolicyProposalReconciler struct {
	client.Client

	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=security.rancher.io,resources=workloadpolicyproposals,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=security.rancher.io,resources=workloadpolicyproposals/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=security.rancher.io,resources=workloadpolicyproposals/finalizers,verbs=update
// +kubebuilder:rbac:groups=security.rancher.io,resources=workloadsecuritypolicies,verbs=get;list;watch;create;patch

func (r *WorkloadPolicyProposalReconciler) Reconcile(
	ctx context.Context,
	req ctrl.Request,
) (ctrl.Result, error) {
	log := log.FromContext(ctx)

	log.Info("workloadpolicyproposal", "req", req)

	var policyProposal securityv1alpha1.WorkloadPolicyProposal
	var err error

	if err = r.Get(ctx, req.NamespacedName, &policyProposal); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	if policyProposal.GetDeletionTimestamp() != nil {
		return ctrl.Result{}, nil
	}

	labels := policyProposal.GetLabels()
	approved := labels[securityv1alpha1.ApprovalLabelKey] == "true"

	if !approved {
		return ctrl.Result{}, nil
	}

	policy := securityv1alpha1.WorkloadSecurityPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      policyProposal.ObjectMeta.Name,
			Namespace: policyProposal.ObjectMeta.Namespace,
		},
	}

	_, err = controllerutil.CreateOrPatch(ctx, r.Client, &policy, func() error {
		policy.Spec = policyProposal.Spec.IntoWorkloadSecurityPolicySpec()
		err = controllerutil.SetControllerReference(&policyProposal, &policy, r.Scheme)
		if err != nil {
			return fmt.Errorf("failed to set controller reference: %w", err)
		}
		return nil
	})
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to call CreateOrPatch: %w", err)
	}

	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *WorkloadPolicyProposalReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&securityv1alpha1.WorkloadPolicyProposal{}).
		Named("workloadpolicyproposal").
		Complete(r)
}
