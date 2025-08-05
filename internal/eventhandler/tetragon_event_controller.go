package eventhandler

import (
	"context"
	"fmt"

	securityv1alpha1 "github.com/neuvector/runtime-enforcement/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/util/workqueue"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/source"
)

type ProcessLearningEvent struct {
	Namespace      string `json:"namespace"`
	Workload       string `json:"workload"`
	WorkloadKind   string `json:"workloadKind"`
	ContainerName  string `json:"containerName"`
	ExecutablePath string `json:"executablePath"`
}

// GetWorkloadSecurityPolicyProposalName returns the name of WorkloadSecurityPolicyProposal
// based on a high level resource and its name.
func GetWorkloadSecurityPolicyProposalName(kind string, resourceName string) (string, error) {
	var shortname string
	switch kind {
	case "Deployment":
		shortname = "deploy"
	case "ReplicaSet":
		shortname = "rs"
	case "DaemonSet":
		shortname = "ds"
	case "CronJob":
		shortname = "cronjob"
	case "Job":
		shortname = "job"
	case "StatefulSet":
		shortname = "sts"
	default:
		return "", fmt.Errorf("unknown kind: %s", kind)
	}
	return shortname + "-" + resourceName, nil
}

type TetragonEventReconciler struct {
	client.Client

	Scheme *runtime.Scheme

	EventChan chan event.TypedGenericEvent[ProcessLearningEvent]
}

// kubebuilder annotations for accessing policy proposals.
// +kubebuilder:rbac:groups=security.rancher.io,resources=workloadsecuritypolicyproposals,verbs=create;get;list;watch;update;patch

func (r *TetragonEventReconciler) Reconcile(
	ctx context.Context,
	req ProcessLearningEvent,
) (ctrl.Result, error) {
	log := log.FromContext(ctx)

	log.Info("Reconciling", "req", req)

	var err error
	var proposalName string

	proposalName, err = GetWorkloadSecurityPolicyProposalName(req.WorkloadKind, req.Workload)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to get proposal name: %w", err)
	}

	log = log.WithValues("proposal", proposalName)

	log.Info("handling learning event")

	policyProposal := &securityv1alpha1.WorkloadSecurityPolicyProposal{
		ObjectMeta: metav1.ObjectMeta{
			Name:      proposalName,
			Namespace: req.Namespace,
		},
	}

	if _, err = controllerutil.CreateOrUpdate(ctx, r.Client, policyProposal, func() error {
		if err = policyProposal.AddProcess(req.ExecutablePath); err != nil {
			return fmt.Errorf("failed to add process to policy proposal: %w", err)
		}
		if len(policyProposal.OwnerReferences) == 0 && policyProposal.Spec.Selector == nil {
			policyProposal.AddPartialOwnerReferenceDetails(req.WorkloadKind, req.Workload)
		}
		return nil
	}); err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to run CreateOrUpdate: %w", err)
	}

	return ctrl.Result{}, nil
}

func (r *TetragonEventReconciler) EnqueueEvent(
	_ context.Context,
	evt ProcessLearningEvent,
) {
	r.EventChan <- event.TypedGenericEvent[ProcessLearningEvent]{Object: evt}
}

// ProcessEventHandler implements handler.TypedEventHandler[ProcessLearningEvent, ProcessLearningEvent].
type ProcessEventHandler struct {
}

func (e ProcessEventHandler) Create(
	_ context.Context,
	_ event.TypedCreateEvent[ProcessLearningEvent],
	_ workqueue.TypedRateLimitingInterface[ProcessLearningEvent],
) {

}

func (e ProcessEventHandler) Update(
	_ context.Context,
	_ event.TypedUpdateEvent[ProcessLearningEvent],
	_ workqueue.TypedRateLimitingInterface[ProcessLearningEvent],
) {

}

func (e ProcessEventHandler) Delete(
	_ context.Context,
	_ event.TypedDeleteEvent[ProcessLearningEvent],
	_ workqueue.TypedRateLimitingInterface[ProcessLearningEvent],
) {

}

func (e ProcessEventHandler) Generic(
	_ context.Context,
	evt event.TypedGenericEvent[ProcessLearningEvent],
	q workqueue.TypedRateLimitingInterface[ProcessLearningEvent],
) {
	q.AddRateLimited(evt.Object)
}

// SetupWithManager sets up the controller with the Manager.
func (r *TetragonEventReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return builder.TypedControllerManagedBy[ProcessLearningEvent](mgr).
		Named("tetragonEvent").
		WatchesRawSource(
			source.TypedChannel(
				r.EventChan,
				&ProcessEventHandler{},
			),
		).
		Complete(r)
}
