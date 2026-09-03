package eventhandler

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/go-logr/logr"
	securityv1alpha1 "github.com/kubewarden/runtime-enforcer/api/v1alpha1"
	"github.com/kubewarden/runtime-enforcer/internal/eventhandler/proposalutils"
	"github.com/kubewarden/runtime-enforcer/internal/eventscraper"
	"github.com/kubewarden/runtime-enforcer/internal/types/loglevel"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/workqueue"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"
)

// DefaultEventChannelBufferSize defines the channel buffer size used to
// deliver events to learning_controller.
// This is a arbitrary number right now and can be fine-tuned or made configurable in the future.
// On a simple kind cluster we saw more than 4200 process exec during the initial process cache dump, so this seems a reasonable default for now.
const (
	DefaultEventChannelBufferSize = 4096
	maxConflictRetries            = 15 // 5ms * (2^0 + 2^1 + ... + 2^15) ~= 328s (~5.5 mins). This would be the maximum time for a process to be learned.

	// The default ratelimiter setting from controller-runtime.
	baseDelay = 5 * time.Millisecond
	maxDelay  = 1000 * time.Second
)

type LearningReconciler struct {
	client.Client

	Scheme            *runtime.Scheme
	eventChan         chan event.TypedGenericEvent[eventscraper.KubeProcessInfo]
	namespaceSelector labels.Selector
	// OwnerRefEnricher can be overridden during testing
	OwnerRefEnricher func(wp *securityv1alpha1.WorkloadPolicyProposal, workloadKind string, workload string)
	ratelimiter      workqueue.TypedRateLimiter[eventscraper.KubeProcessInfo]
}

func NewLearningReconciler(
	client client.Client,
	selector labels.Selector,
) *LearningReconciler {
	return &LearningReconciler{
		Client: client,
		eventChan: make(
			chan event.TypedGenericEvent[eventscraper.KubeProcessInfo],
			DefaultEventChannelBufferSize,
		),
		namespaceSelector: selector,
		OwnerRefEnricher: func(wp *securityv1alpha1.WorkloadPolicyProposal, workloadKind string, workload string) {
			wp.OwnerReferences = []metav1.OwnerReference{
				{
					Kind: workloadKind,
					Name: workload,
				},
			}
		},
		ratelimiter: workqueue.NewTypedItemExponentialFailureRateLimiter[eventscraper.KubeProcessInfo](
			baseDelay,
			maxDelay,
		),
	}
}

// handleAdmissionError deals with the errors returned by our mutating webhook.
func (r *LearningReconciler) handleAdmissionError(logger logr.Logger, err error) error {
	var apistatus apierrors.APIStatus
	if !errors.As(err, &apistatus) {
		return err
	}

	switch apistatus.Status().Code {
	case http.StatusUnprocessableEntity:
		// The item is rejected by the webhook.
		// This means something seriously wrong with the request and we should stop retrying.
		logger.Error(
			err,
			"Failed to update WorkloadPolicyProposal because the proposal is rejected by the webhook",
		)
		return nil
	case http.StatusGone:
		// This happens when the top-level workload is deleted.
		// We don't need to retry anymore.
		logger.V(loglevel.VerbosityDebug).Info(
			"Failed to update WorkloadPolicyProposal because the owner workload has been deleted",
		)
		return nil
	case http.StatusConflict:
		// This happens when there are multiple agents trying to update the same WorkloadPolicyProposal at the same time.
		// This is by design, but we should return the error as it is for our rate limiter to retry.
		// Both conflict and already exists errors fall in this category.
		return err
	case http.StatusForbidden:
		// This happens when the admission webhook rejects the request normally without specifying a special error code.
		// This means transient errors that we should retry.
		return err
	case http.StatusInternalServerError:
		// This happens when the admission webhook is down. We should retry.
		return err
	default:
		return fmt.Errorf(
			"error code %d received when running CreateOrUpdate: %w",
			apistatus.Status().Code,
			err,
		)
	}
}

// kubebuilder annotations for accessing policy proposals and namespaces.
// +kubebuilder:rbac:groups="",resources=namespaces,verbs=get;list;watch
// +kubebuilder:rbac:groups=security.rancher.io,resources=workloadpolicyproposals,verbs=create;get;list;watch;update;patch
// +kubebuilder:rbac:groups=security.rancher.io,resources=workloadpolicies,verbs=list;watch

// skipOrLearn decides whether to skip learning.
//
// Skip (true, nil) when:
//   - req.PolicyName is set (pod already has security.rancher.io/policy).
//   - the proposal does not exist but a WorkloadPolicy with workloadpolicy.security.rancher.io/promoted-from=<proposalName> exists.
//
// Learn (false, nil) when:
//   - the proposal exists (no security.rancher.io/policy label set on the proposal).
//   - the proposal does not exist but no WorkloadPolicy with workloadpolicy.security.rancher.io/promoted-from=<proposalName> exists.
func (r *LearningReconciler) skipOrLearn(
	ctx context.Context,
	req eventscraper.KubeProcessInfo,
	proposalName string,
	policyProposal *securityv1alpha1.WorkloadPolicyProposal,
) (bool, error) {
	logger := log.FromContext(ctx)

	if req.PolicyName != "" {
		logger.V(3).Info( //nolint:mnd // 3 is the verbosity level for detailed debug info
			"Ignoring learning event because pod is already bound to a WorkloadPolicy",
			"workload", req.Workload,
			"workload_kind", req.WorkloadKind,
			"policy", req.PolicyName,
		)
		return true, nil
	}

	err := r.Client.Get(ctx, types.NamespacedName{
		Namespace: req.Namespace,
		Name:      proposalName,
	}, policyProposal)
	if err == nil {
		return false, nil
	}
	if !apierrors.IsNotFound(err) {
		return false, fmt.Errorf("failed to get WorkloadPolicyProposal before learning update: %w", err)
	}

	alreadyPromoted, err := proposalutils.HasProposalBeenPromoted(
		ctx, r.Client, req.Namespace, proposalName,
	)
	if err != nil {
		return false, err
	}

	if alreadyPromoted {
		logger.V(3).Info( //nolint:mnd // 3 is the verbosity level for detailed debug info
			"Ignoring learning event because workload already has a promoted WorkloadPolicy",
			"workload", req.Workload,
			"workload_kind", req.WorkloadKind,
			"proposal", proposalName,
		)
		return true, nil
	}

	return false, nil
}

// Reconcile maintains a retry mechanism with exponential backoff when processing learning events.
func (r *LearningReconciler) Reconcile(
	ctx context.Context,
	req eventscraper.KubeProcessInfo,
) (ctrl.Result, error) {
	log := log.FromContext(ctx)

	ret, err := r.reconcile(ctx, req)
	if err != nil {
		// We use our own ratelimiter to deal with by-design conflict errors.
		// We're totally fine with controller-runtime's ratelimiter by returning `Requeue: true`,
		// but this field is deprecated, and we'd like to make sure that it won't retry forever.
		// See also: https://github.com/kubernetes-sigs/controller-runtime/pull/3107
		if !apierrors.IsConflict(err) && !apierrors.IsAlreadyExists(err) {
			return ret, err
		}

		if r.ratelimiter.NumRequeues(req) > maxConflictRetries {
			// we remove the item from ratelimiter and make sure controller-runtime won't retry it anymore.
			r.ratelimiter.Forget(req)
			return ctrl.Result{}, reconcile.TerminalError(err)
		}

		requeueAfter := r.ratelimiter.When(req)

		log.V(loglevel.VerbosityDebug).
			Info("Reconciliation failed due to conflict. Retry with backoff", "req", req, "delay", requeueAfter, "error", err)

		return ctrl.Result{RequeueAfter: requeueAfter}, nil
	}

	r.ratelimiter.Forget(req)
	return ret, nil
}

// reconcile receives learning events and creates/updates WorkloadPolicyProposal resources accordingly.
func (r *LearningReconciler) reconcile(
	ctx context.Context,
	req eventscraper.KubeProcessInfo,
) (ctrl.Result, error) { //nolint:unparam // we want to keep it compatible with controller-runtime.
	logger := log.FromContext(ctx).WithValues(
		"namespace", req.Namespace,
		"workload", req.Workload,
		"workload_kind", req.WorkloadKind,
		"exe", req.ExecutablePath,
	)

	logger.V(loglevel.VerbosityDebug).Info("Reconciling", "req", req)

	var err error
	var proposalName string

	if req.WorkloadKind == "Pod" {
		// We don't support learning on standalone pods

		logger.V(loglevel.VerbosityDebug).Info(
			"Ignoring learning event",
		)

		return ctrl.Result{}, nil
	}

	var ns corev1.Namespace
	if err = r.Client.Get(ctx, types.NamespacedName{Name: req.Namespace}, &ns); err != nil {
		if apierrors.IsNotFound(err) {
			logger.V(loglevel.VerbosityDebug).Info(
				"Namespace not found while evaluating learning namespace selector",
			)
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, fmt.Errorf("failed to get namespace %s: %w", req.Namespace, err)
	}
	if !r.namespaceSelector.Matches(labels.Set(ns.GetLabels())) {
		return ctrl.Result{}, nil
	}

	proposalName, err = proposalutils.GetWorkloadPolicyProposalName(req.WorkloadKind, req.Workload)
	if err != nil {
		return ctrl.Result{}, reconcile.TerminalError(fmt.Errorf("failed to get proposal name: %w", err))
	}

	policyProposal := &securityv1alpha1.WorkloadPolicyProposal{
		Name:      proposalName,
		Namespace: req.Namespace,
	}

	skip, err := r.skipOrLearn(ctx, req, proposalName, policyProposal)
	if err != nil || skip {
		return ctrl.Result{}, err
	}

	if _, err = controllerutil.CreateOrUpdate(ctx, r.Client, policyProposal, func() error {
		// We don't learn any new process if the policy proposal was promoted
		// to an actual policy
		if _, hasPromotionLabel := policyProposal.HasPromotionLabel(); hasPromotionLabel {
			return nil
		}

		if policyProposal.IsFull() {
			logger.Info("proposal is full, cannot add new executables",
				"proposal", policyProposal.NamespacedName(),
				"exe", req.ExecutablePath,
			)
			return nil
		}
		policyProposal.AddProcess(req.ContainerName, req.ExecutablePath)

		// If the owner reference is already there we do nothing.
		// We should always have the owner reference populated unless we are creating the resource for the first time.
		if len(policyProposal.OwnerReferences) != 0 {
			return nil
		}

		// if we don't populate a partial owner reference here the webhook won't be able to populate the owner reference because it doesn't know who is the owner.
		r.OwnerRefEnricher(policyProposal, req.WorkloadKind, req.Workload)
		return nil
	}); err != nil {
		return ctrl.Result{}, r.handleAdmissionError(logger, err)
	}
	return ctrl.Result{}, nil
}

func (r *LearningReconciler) EnqueueEvent(evt eventscraper.KubeProcessInfo) {
	r.eventChan <- event.TypedGenericEvent[eventscraper.KubeProcessInfo]{Object: evt}
}

// ProcessEventHandler implements handler.TypedEventHandler[eventscraper.KubeProcessInfo, eventscraper.KubeProcessInfo].
type ProcessEventHandler struct {
}

func (e ProcessEventHandler) Create(
	_ context.Context,
	_ event.TypedCreateEvent[eventscraper.KubeProcessInfo],
	_ workqueue.TypedRateLimitingInterface[eventscraper.KubeProcessInfo],
) {

}

func (e ProcessEventHandler) Update(
	_ context.Context,
	_ event.TypedUpdateEvent[eventscraper.KubeProcessInfo],
	_ workqueue.TypedRateLimitingInterface[eventscraper.KubeProcessInfo],
) {

}

func (e ProcessEventHandler) Delete(
	_ context.Context,
	_ event.TypedDeleteEvent[eventscraper.KubeProcessInfo],
	_ workqueue.TypedRateLimitingInterface[eventscraper.KubeProcessInfo],
) {

}

func (e ProcessEventHandler) Generic(
	_ context.Context,
	evt event.TypedGenericEvent[eventscraper.KubeProcessInfo],
	q workqueue.TypedRateLimitingInterface[eventscraper.KubeProcessInfo],
) {
	q.AddRateLimited(evt.Object)
}

// SetupWithManager sets up the controller with the Manager.
func (r *LearningReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return builder.TypedControllerManagedBy[eventscraper.KubeProcessInfo](mgr).
		Named("learningEvent").
		WatchesRawSource(
			source.TypedChannel(
				r.eventChan,
				&ProcessEventHandler{},
			),
		).
		Complete(r)
}
