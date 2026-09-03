package controller

import (
	"context"
	"fmt"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	securityv1alpha1 "github.com/kubewarden/runtime-enforcer/api/v1alpha1"
	"github.com/kubewarden/runtime-enforcer/internal/eventhandler/proposalutils"
)

// WorkloadPolicyProposalReconciler reconciles a WorkloadPolicyProposal object.
type WorkloadPolicyProposalReconciler struct {
	client.Client

	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=security.rancher.io,resources=workloadpolicyproposals,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=security.rancher.io,resources=workloadpolicies,verbs=get;list;watch;create;patch

func (r *WorkloadPolicyProposalReconciler) Reconcile(
	ctx context.Context,
	req ctrl.Request,
) (ctrl.Result, error) {
	log := log.FromContext(ctx)

	log.Info("workloadpolicyproposal", "req", req)

	var proposal securityv1alpha1.WorkloadPolicyProposal
	if err := r.Get(ctx, req.NamespacedName, &proposal); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	if proposal.GetDeletionTimestamp() != nil {
		return ctrl.Result{}, nil
	}

	// After a proposal is promoted and deleted, an agent can recreate a WorkloadPolicyProposal
	// at the same time. If a WorkloadPolicy already exists with promoted-from=<proposalName>,
	// treat the proposal as leftover and delete it. This is eventually reconciled on the controller-runtime
	// resync (SyncPeriod, 10 hours by default) if both the proposal and the policy are still in the cluster.
	alreadyPromoted, err := proposalutils.HasProposalBeenPromoted(
		ctx, r.Client,
		proposal.Namespace,
		proposal.Name,
	)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to check promoted WorkloadPolicy: %w", err)
	}
	if alreadyPromoted {
		log.Info("Deleting WorkloadPolicyProposal; promoted WorkloadPolicy already exists",
			"proposal", proposal.Name)
		if err = r.Delete(ctx, &proposal); err != nil {
			return ctrl.Result{}, client.IgnoreNotFound(err)
		}
		return ctrl.Result{}, nil
	}

	mode, hasPromotionLabel := proposal.HasPromotionLabel()
	if !hasPromotionLabel {
		return ctrl.Result{}, nil
	}

	policy := securityv1alpha1.WorkloadPolicy{
		Name:      proposal.Name,
		Namespace: proposal.Namespace,
		Spec:      proposal.Spec.IntoWorkloadPolicySpec(mode),
	}
	if err = policy.SetPromotedLabel(proposal.Name); err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to set promoted label: %w", err)
	}

	if err = r.Create(ctx, &policy); err != nil {
		if apierrors.IsAlreadyExists(err) {
			log.Info("WorkloadPolicy already exists, skipping creation", "policy", policy.NamespacedName())
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, fmt.Errorf("failed to create WorkloadPolicy: %w", err)
	}

	// Once we successfully promote the proposal into a policy, we no longer
	// need the proposal to remain in the cluster.
	if err = r.Delete(ctx, &proposal); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
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
