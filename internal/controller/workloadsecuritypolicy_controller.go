package controller

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	tetragonv1alpha1 "github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	securityv1alpha1 "github.com/neuvector/runtime-enforcer/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// WorkloadSecurityPolicyReconciler reconciles a WorkloadSecurityPolicy object.
type WorkloadSecurityPolicyReconciler struct {
	client.Client

	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=security.rancher.io,resources=workloadsecuritypolicies,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=security.rancher.io,resources=workloadsecuritypolicies/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=security.rancher.io,resources=workloadsecuritypolicies/finalizers,verbs=update
// +kubebuilder:rbac:groups=cilium.io,resources=tracingpoliciesnamespaced,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=pods,verbs=get;list;watch

func (r *WorkloadSecurityPolicyReconciler) Reconcile(
	ctx context.Context,
	req ctrl.Request,
) (ctrl.Result, error) {
	log := log.FromContext(ctx)

	log.Info("workloadsecuritypolicy", "req", req)

	var policy securityv1alpha1.WorkloadSecurityPolicy
	var err error
	if err = r.Get(ctx, req.NamespacedName, &policy); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	if policy.GetDeletionTimestamp() != nil {
		return r.handleDeletion(ctx, &policy)
	}

	tetragonPolicy := tetragonv1alpha1.TracingPolicyNamespaced{
		ObjectMeta: metav1.ObjectMeta{
			Name:      policy.Name,
			Namespace: policy.Namespace,
		},
	}

	_, err = controllerutil.CreateOrPatch(ctx, r.Client, &tetragonPolicy, func() error {
		tetragonPolicy.Spec = policy.Spec.IntoTetragonPolicySpec()
		err = controllerutil.SetControllerReference(&policy, &tetragonPolicy, r.Scheme)
		if err != nil {
			return fmt.Errorf("failed to set controller reference: %w", err)
		}
		return nil
	})
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to call CreateOrPatch: %w", err)
	}

	return ctrl.Result{}, r.updateStatus(ctx, &policy)
}

func (r *WorkloadSecurityPolicyReconciler) handleDeletion(
	ctx context.Context,
	policy *securityv1alpha1.WorkloadSecurityPolicy,
) (ctrl.Result, error) {
	log := log.FromContext(ctx)

	if !controllerutil.ContainsFinalizer(policy, WorkloadSecurityPolicyFinalizer) {
		return ctrl.Result{}, nil
	}

	hasPods, err := r.hasPodsUsingPolicy(ctx, policy)
	if err != nil {
		return ctrl.Result{}, err
	}
	if hasPods {
		log.Info("policy is still in use by pods, cannot delete", "policy", policy.Name)
		return ctrl.Result{}, nil
	}

	tetragonPolicy := tetragonv1alpha1.TracingPolicyNamespaced{
		ObjectMeta: metav1.ObjectMeta{
			Name:      policy.Name,
			Namespace: policy.Namespace,
		},
	}
	if deleteErr := r.Delete(ctx, &tetragonPolicy); deleteErr != nil && !errors.IsNotFound(deleteErr) {
		return ctrl.Result{}, fmt.Errorf("failed to delete tetragon policy: %w", deleteErr)
	}

	controllerutil.RemoveFinalizer(policy, WorkloadSecurityPolicyFinalizer)
	if updateErr := r.Update(ctx, policy); updateErr != nil {
		return ctrl.Result{}, fmt.Errorf("failed to remove finalizer: %w", updateErr)
	}

	log.Info("successfully removed finalizer and cleaned up resources")
	return ctrl.Result{}, nil
}

func (r *WorkloadSecurityPolicyReconciler) hasPodsUsingPolicy(
	ctx context.Context,
	policy *securityv1alpha1.WorkloadSecurityPolicy,
) (bool, error) {
	// If no selector is specified, we can't determine which pods use the policy
	// In this case, we'll assume no pods are using it
	if policy.Spec.Selector == nil {
		return false, nil
	}

	selector, err := metav1.LabelSelectorAsSelector(policy.Spec.Selector)
	if err != nil {
		return false, fmt.Errorf("failed to convert label selector: %w", err)
	}

	podList := &corev1.PodList{}
	listOpts := []client.ListOption{
		client.InNamespace(policy.Namespace),
	}

	if listErr := r.List(ctx, podList, listOpts...); listErr != nil {
		return false, fmt.Errorf("failed to list pods: %w", listErr)
	}

	for _, pod := range podList.Items {
		if pod.GetDeletionTimestamp() != nil {
			continue
		}
		if selector.Matches(labels.Set(pod.Labels)) {
			return true, nil
		}
	}

	return false, nil
}

func (r *WorkloadSecurityPolicyReconciler) updateStatus(
	ctx context.Context,
	policy *securityv1alpha1.WorkloadSecurityPolicy,
) error {
	newPolicy := policy.DeepCopy()
	newPolicy.Status.ObservedGeneration = newPolicy.Generation
	newPolicy.Status.State = securityv1alpha1.DeployedState
	return r.Status().Update(ctx, newPolicy)
}

// mapPodsToPolicies maps pod events to WorkloadSecurityPolicy reconciles.
// When a pod is deleted, it triggers reconciles for all policies in the same namespace
// that might match that pod, allowing policies waiting for deletion to proceed.
func (r *WorkloadSecurityPolicyReconciler) mapPodsToPolicies(
	ctx context.Context,
	obj client.Object,
) []reconcile.Request {
	pod, ok := obj.(*corev1.Pod)
	if !ok {
		return []reconcile.Request{}
	}

	logger := log.FromContext(ctx)

	policyList := &securityv1alpha1.WorkloadSecurityPolicyList{}
	if err := r.List(ctx, policyList, client.InNamespace(pod.Namespace)); err != nil {
		logger.Error(
			err,
			"failed to list WorkloadSecurityPolicies when mapping pod to policies",
			"pod",
			pod.Name,
			"namespace",
			pod.Namespace,
		)
		return []reconcile.Request{}
	}

	var requests []reconcile.Request
	for _, policy := range policyList.Items {
		if policy.GetDeletionTimestamp() == nil {
			continue
		}

		if policy.Spec.Selector == nil {
			continue
		}

		selector, err := metav1.LabelSelectorAsSelector(policy.Spec.Selector)
		if err != nil {
			logger.Error(err, "failed to convert label selector when mapping pod to policies", "policy", policy.Name)
			continue
		}

		if selector.Matches(labels.Set(pod.Labels)) {
			requests = append(requests, reconcile.Request{
				NamespacedName: types.NamespacedName{
					Name:      policy.Name,
					Namespace: policy.Namespace,
				},
			})
			logger.Info(
				"pod deletion triggered policy reconcile",
				"pod",
				pod.Name,
				"policy",
				policy.Name,
				"namespace",
				pod.Namespace,
			)
		}
	}

	return requests
}

// SetupWithManager sets up the controller with the Manager.
func (r *WorkloadSecurityPolicyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if err := tetragonv1alpha1.AddToScheme(mgr.GetScheme()); err != nil {
		return err
	}
	return ctrl.NewControllerManagedBy(mgr).
		For(&securityv1alpha1.WorkloadSecurityPolicy{}).
		Watches(
			&corev1.Pod{},
			handler.EnqueueRequestsFromMapFunc(r.mapPodsToPolicies),
		).
		Named("workloadsecuritypolicy").
		Complete(r)
}
