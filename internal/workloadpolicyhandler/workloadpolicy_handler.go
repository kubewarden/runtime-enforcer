package workloadpolicyhandler

import (
	"context"
	"fmt"
	"log/slog"
	"sync/atomic"

	"k8s.io/apimachinery/pkg/api/errors"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	"github.com/kubewarden/runtime-enforcer/api/v1alpha1"
	"github.com/kubewarden/runtime-enforcer/internal/resolver"
	"github.com/kubewarden/runtime-enforcer/internal/types/policymode"
	agentv1 "github.com/kubewarden/runtime-enforcer/proto/agent/v1"
)

// WorkloadPolicyHandler reconciles a WorkloadPolicy object.
type WorkloadPolicyHandler struct {
	client.Client

	logger    *slog.Logger
	resolver  *resolver.Resolver
	hasSynced atomic.Bool
}

func NewWorkloadPolicyHandler(
	client client.Client,
	logger *slog.Logger,
	resolver *resolver.Resolver,
) *WorkloadPolicyHandler {
	return &WorkloadPolicyHandler{
		Client:   client,
		logger:   logger,
		resolver: resolver,
	}
}

// +kubebuilder:rbac:groups=security.rancher.io,resources=workloadpolicies,verbs=get;list;watch

func (r *WorkloadPolicyHandler) Reconcile(
	ctx context.Context,
	req ctrl.Request,
) (ctrl.Result, error) {
	var err error

	var wp v1alpha1.WorkloadPolicy
	if err = r.Get(ctx, req.NamespacedName, &wp); err != nil {
		if !errors.IsNotFound(err) {
			return ctrl.Result{}, fmt.Errorf("failed to get WorkloadPolicy '%s': %w", req.NamespacedName, err)
		}
		// The item has been removed.
		if err = r.resolver.HandleWPDelete(&v1alpha1.WorkloadPolicy{
			Name:      req.Name,
			Namespace: req.Namespace,
		}); err != nil {
			return ctrl.Result{}, fmt.Errorf(
				"failed to delete WorkloadPolicy '%s': %w",
				req.NamespacedName,
				err,
			)
		}

		return ctrl.Result{}, nil
	}

	if err = r.resolver.ReconcileWP(&wp); err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to update WorkloadPolicy '%s': %w", req.NamespacedName, err)
	}

	return ctrl.Result{}, nil
}

// HasSynced returns nil if the handler has reconciled with all existing WorkloadPolicies.
// Otherwise, it returns the error during the validation.
// This function is supposed to be used as part of the startup probe, so we know the enforcement is ready for the old pod to stop during the rolling update.
func (r *WorkloadPolicyHandler) HasSynced(ctx context.Context) error {
	// hasSynced has to be protected as startup probe can be called by many callers.
	if r.hasSynced.Load() {
		return nil
	}

	var wps v1alpha1.WorkloadPolicyList
	if err := r.List(ctx, &wps); err != nil {
		return fmt.Errorf("failed to list WorkloadPolicies during HasSynced check: %w", err)
	}

	statuses := r.resolver.GetPolicyStatuses()
	for _, wp := range wps.Items {
		status, ok := statuses[wp.NamespacedName()]
		if !ok {
			return fmt.Errorf("policy status not found for WorkloadPolicy '%s'", wp.NamespacedName())
		}
		if status.State != agentv1.PolicyState_POLICY_STATE_READY {
			return fmt.Errorf("policy status is not ready for WorkloadPolicy '%s'", wp.NamespacedName())
		}
		mode := policymode.ParsePolicyModeToProto(wp.Spec.Mode)
		if status.Mode != mode {
			return fmt.Errorf("policy status is not ready for WorkloadPolicy '%s'", wp.NamespacedName())
		}
	}

	// at this point, all workload policies have been synced.
	r.hasSynced.Store(true)

	return nil
}

func (r *WorkloadPolicyHandler) IsSynchronized() bool {
	return r.hasSynced.Load()
}

// SetupWithManager sets up the controller with the Manager.
func (r *WorkloadPolicyHandler) SetupWithManager(mgr ctrl.Manager) error {
	err := ctrl.NewControllerManagedBy(mgr).
		For(&v1alpha1.WorkloadPolicy{}).
		Named("workloadpolicy").
		WithEventFilter(predicate.GenerationChangedPredicate{}).
		Complete(r)
	if err != nil {
		return fmt.Errorf("unable to set up WorkloadPolicy handler: %w", err)
	}
	return nil
}
