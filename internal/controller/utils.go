package controller

import (
	"context"
	"fmt"

	securityv1alpha1 "github.com/neuvector/runtime-enforcement/api/v1alpha1"
	"github.com/neuvector/runtime-enforcement/internal/policy"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/util/retry"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

// UpdateWorkloadSecurityPolicyProposal creates a WorkloadSecurityPolicyProposal
// based on its high level resource.
func UpdateWorkloadSecurityPolicyProposal(
	owner metav1.Object,
	proposal *securityv1alpha1.WorkloadSecurityPolicyProposal,
) error {
	var selector *metav1.LabelSelector
	switch t := owner.(type) {
	case *appsv1.Deployment:
		selector = t.Spec.Selector
	case *appsv1.DaemonSet:
		selector = t.Spec.Selector
	case *appsv1.ReplicaSet:
		selector = t.Spec.Selector
	case *appsv1.StatefulSet:
		selector = t.Spec.Selector
	case *batchv1.CronJob:
		selector = t.Spec.JobTemplate.Spec.Selector
	case *batchv1.Job:
		selector = t.Spec.Selector
	default:
		return fmt.Errorf("unexpected type %T", t)
	}

	proposal.Spec = securityv1alpha1.WorkloadSecurityPolicyProposalSpec{
		Selector: selector,
		Rules: securityv1alpha1.WorkloadSecurityPolicyProposalRules{
			Executables: securityv1alpha1.WorkloadSecurityPolicyProposalExecutables{},
		},
	}

	return nil
}

type CommonReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=security.rancher.io,resources=workloadsecuritypolicyproposals,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=security.rancher.io,resources=workloadsecuritypolicyproposals/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=security.rancher.io,resources=workloadsecuritypolicyproposals/finalizers,verbs=update

func (r *CommonReconciler) reconcileWithProposal(
	ctx context.Context,
	kind string,
	obj metav1.Object,
) (ctrl.Result, error) {
	var err error

	// These two resources are often created as an intermediate object.
	// Ignore them if they have a corresponding owner reference
	switch t := obj.(type) {
	case *appsv1.ReplicaSet:
		if len(t.OwnerReferences) > 0 && t.OwnerReferences[0].Kind == "Deployment" {
			return ctrl.Result{}, nil
		}
	case *batchv1.Job:
		if len(t.OwnerReferences) > 0 && t.OwnerReferences[0].Kind == "CronJob" {
			return ctrl.Result{}, nil
		}
	}

	var proposal securityv1alpha1.WorkloadSecurityPolicyProposal
	proposal.Namespace = obj.GetNamespace()
	proposal.Name, err = policy.GetWorkloadSecurityPolicyProposalName(kind, obj.GetName())
	if err != nil {
		//nolint:nilerr // couldn't find the top level resource or unknown workload.  We don't want it keep retrying.
		return ctrl.Result{}, nil
	}

	if err = retry.RetryOnConflict(retry.DefaultBackoff, func() error {
		_, err = controllerutil.CreateOrUpdate(ctx, r.Client, &proposal, func() error {
			err = UpdateWorkloadSecurityPolicyProposal(obj, &proposal)
			if err != nil {
				return fmt.Errorf("failed to update workload security policy proposal: %w", err)
			}
			err = controllerutil.SetControllerReference(obj, &proposal, r.Scheme)
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
		return ctrl.Result{}, fmt.Errorf("failed to create workload security policy proposal: %w", err)
	}

	return ctrl.Result{}, nil
}
