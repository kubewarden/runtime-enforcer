package eventhandler

import (
	"context"
	"fmt"
	"time"

	securityv1alpha1 "github.com/neuvector/runtime-enforcement/api/v1alpha1"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/client-go/util/workqueue"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/source"
)

// DefaultEventChannelBufferSize defines the channel buffer size used to
// deliver Tetragon events to tetragon_event_controller.
// This is a arbitrary number right now and can be fine-tuned or made configurable in the future.
// On a simple kind cluster we saw more than 4200 process exec during the initial process cache dump from Tetragon, so this seems a reasonable default for now.
const DefaultEventChannelBufferSize = 4096

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
	ret := shortname + "-" + resourceName

	// The max name length in k8s
	if len(ret) > validation.DNS1123SubdomainMaxLength {
		return "", fmt.Errorf("the name %s exceeds the maximum name length", ret)
	}

	return shortname + "-" + resourceName, nil
}

type TetragonEventReconciler struct {
	client.Client

	Scheme    *runtime.Scheme
	eventChan chan event.TypedGenericEvent[ProcessLearningEvent]
	tracer    trace.Tracer
}

func NewTetragonEventReconciler(client client.Client, scheme *runtime.Scheme) *TetragonEventReconciler {
	return &TetragonEventReconciler{
		Client:    client,
		Scheme:    scheme,
		eventChan: make(chan event.TypedGenericEvent[ProcessLearningEvent], DefaultEventChannelBufferSize),
		tracer:    otel.Tracer("runtime-enforcement-learner"),
	}
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

	var result controllerutil.OperationResult

	if result, err = controllerutil.CreateOrUpdate(ctx, r.Client, policyProposal, func() error {
		// We don't learn any new process if the policy proposal was promoted
		// to an actual policy
		labels := policyProposal.GetLabels()
		if labels[securityv1alpha1.ApprovalLabelKey] == "true" {
			return nil
		}

		if innerErr := policyProposal.AddProcess(req.ExecutablePath); err != nil {
			return fmt.Errorf("failed to add process to policy proposal: %w", innerErr)
		}

		// We do not inject partial owner reference when selector is available.
		// This is to facilitate unit tests.
		if len(policyProposal.OwnerReferences) == 0 && policyProposal.Spec.Selector == nil {
			policyProposal.AddPartialOwnerReferenceDetails(req.WorkloadKind, req.Workload)
		}
		return nil
	}); err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to run CreateOrUpdate: %w", err)
	}

	// Emit trace when a new process is learned.
	if result != controllerutil.OperationResultNone {
		var span trace.Span
		now := time.Now()
		_, span = r.tracer.Start(ctx, "process learned")
		span.SetAttributes(
			attribute.String("evt.time", now.Format(time.RFC3339)),
			attribute.Int64("evt.rawtime", now.UnixNano()),
			attribute.String("k8s.ns.name", req.Namespace),
			attribute.String("k8s.workload.kind", req.WorkloadKind),
			attribute.String("k8s.workload.name", req.Workload),
			attribute.String("container.name", req.ContainerName),
			attribute.String("proc.exepath", req.ExecutablePath),
		)
		span.End()
	}

	return ctrl.Result{}, nil
}

func (r *TetragonEventReconciler) EnqueueEvent(
	_ context.Context,
	evt ProcessLearningEvent,
) {
	r.eventChan <- event.TypedGenericEvent[ProcessLearningEvent]{Object: evt}
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
				r.eventChan,
				&ProcessEventHandler{},
			),
		).
		Complete(r)
}
