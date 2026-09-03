package controller

import (
	"context"
	"fmt"
	"time"

	"github.com/go-logr/logr"
	"github.com/kubewarden/runtime-enforcer/api/v1alpha1"
	"github.com/kubewarden/runtime-enforcer/internal/grpcexporter"
	"github.com/kubewarden/runtime-enforcer/internal/types/loglevel"

	"go.opentelemetry.io/otel/attribute"
	otellog "go.opentelemetry.io/otel/log"
	"go.opentelemetry.io/otel/metric"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

// +kubebuilder:rbac:groups="",resources=pods,verbs=get;list;watch
// +kubebuilder:rbac:groups=security.rancher.io,resources=workloadpolicies,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=security.rancher.io,resources=workloadpolicies/status,verbs=get;update;patch

// WorkloadPolicyStatusSync reconciles a WorkloadPolicy status.
type WorkloadPolicyStatusSync struct {
	client.Client

	agentClientPool       *grpcexporter.AgentClientPool
	updateInterval        time.Duration
	logger                logr.Logger
	eventLogger           otellog.Logger
	activeViolationsGauge metric.Int64Gauge
}

// WorkloadPolicyStatusSyncConfig holds the configuration for the WorkloadPolicyStatusSync.
type WorkloadPolicyStatusSyncConfig struct {
	AgentPoolConf         grpcexporter.AgentClientPoolConfig
	UpdateInterval        time.Duration
	EventLogger           otellog.Logger
	ActiveViolationsGauge metric.Int64Gauge
}

func NewWorkloadPolicyStatusSync(
	c client.Client,
	config *WorkloadPolicyStatusSyncConfig,
) (*WorkloadPolicyStatusSync, error) {
	if config.UpdateInterval <= 0 {
		return nil, fmt.Errorf("invalid update interval: %v", config.UpdateInterval)
	}

	agentClientPool, err := grpcexporter.NewAgentClientPool(config.AgentPoolConf)
	if err != nil {
		return nil, fmt.Errorf("failed to create agent client pool: %w", err)
	}

	return &WorkloadPolicyStatusSync{
		Client:                c,
		agentClientPool:       agentClientPool,
		updateInterval:        config.UpdateInterval,
		eventLogger:           config.EventLogger,
		activeViolationsGauge: config.ActiveViolationsGauge,
	}, nil
}

func (r *WorkloadPolicyStatusSync) Start(ctx context.Context) error {
	r.logger = log.FromContext(ctx).WithName("WorkloadPolicyStatusSync")
	r.logger.Info("Starting with", "interval", r.updateInterval.String())
	for {
		select {
		case <-ctx.Done():
			r.logger.Info("Closing")
			return nil
		// today we keep this runnable single-threaded so after each sync we wait again `updateInterval`.
		case <-time.After(r.updateInterval):
			if err := r.sync(ctx); err != nil {
				r.logger.Error(err, "Failed to sync")
			}
		}
	}
}

func (r *WorkloadPolicyStatusSync) sync(
	ctx context.Context,
) error {
	// As first step, we list all WorkloadPolicies, if there are none, we can reschedule and exit early
	var wpList v1alpha1.WorkloadPolicyList
	if err := r.List(ctx, &wpList); err != nil {
		return err
	}

	if len(wpList.Items) == 0 {
		r.logger.V(loglevel.VerbosityDebug).Info("No WorkloadPolicies found, retrying later")
		return nil
	}

	clients, err := r.agentClientPool.UpdatePool(ctx, r.Client)
	if err != nil {
		return err
	}

	nodeStatusByPolicy := r.getNodeStatusByPolicy(ctx, clients, wpList.Items)

	if clients, err = r.agentClientPool.UpdatePool(ctx, r.Client); err != nil {
		return err
	}
	violationsByPolicy := r.getViolationsByPolicy(ctx, clients)

	// Now we iterate over all WSPs and update their status based on the collected policies status from the agents
	for _, wp := range wpList.Items {
		policyName := wp.NamespacedName()
		if err = r.processWorkloadPolicy(
			ctx,
			&wp,
			nodeStatusByPolicy[policyName],
			violationsByPolicy[policyName],
		); err != nil {
			r.logger.Error(
				err,
				"failed to process workload policy",
				"policy", policyName,
			)
			continue
		}

		if r.activeViolationsGauge != nil {
			r.activeViolationsGauge.Record(
				ctx,
				int64(wp.Status.ActiveViolationCount),
				metric.WithAttributes(
					attribute.String("policy.name", wp.Name),
					attribute.String("k8s.namespace.name", wp.Namespace),
				),
			)
		}
	}

	return nil
}

// getViolationsByPolicy gets all the violations for a single policy.
func (r *WorkloadPolicyStatusSync) getViolationsByPolicy(
	ctx context.Context,
	clients map[string]grpcexporter.AgentClientAPI,
) map[string][]v1alpha1.ViolationRecord {
	violationsByPolicy := make(map[string][]v1alpha1.ViolationRecord)
	for nodeName, client := range clients {
		if client == nil {
			r.logger.Info("cannot get a agent client for the node", "node", nodeName)
			continue
		}
		pbViolations, err := client.ScrapeViolations(ctx)
		if err != nil {
			r.agentClientPool.MarkStaleAgentClient(nodeName)
			r.logger.Error(err, "failed to scrape violations", "node", nodeName)
			continue
		}
		for _, v := range pbViolations {
			namespacedName := v.GetPolicyName()
			rec := v1alpha1.ViolationRecord{
				LastObservedTimestamp: metav1.NewTime(v.GetTimestamp().AsTime()),
				PodName:               v.GetPodName(),
				ContainerName:         v.GetContainerName(),
				ExecutablePath:        v.GetExecutablePath(),
				NodeName:              v.GetNodeName(),
				Action:                v.GetAction(),
				WorkloadName:          v.GetWorkloadName(),
				WorkloadKind:          v.GetWorkloadKind(),
			}
			violationsByPolicy[namespacedName] = append(violationsByPolicy[namespacedName], rec)
		}
	}

	return violationsByPolicy
}

func (r *WorkloadPolicyStatusSync) emitAcknowledgedViolationOtelLog(
	ctx context.Context,
	policyName, namespace string,
	ack v1alpha1.AcknowledgedViolationRecord,
) {
	if r.eventLogger == nil {
		return
	}

	var rec otellog.Record
	violation := ack.Violation
	rec.SetEventName("policy_violation_acknowledged")
	rec.SetSeverity(otellog.SeverityInfo)
	rec.SetBody(attribute.StringValue("policy_violation_acknowledged"))
	rec.SetTimestamp(time.Now())
	rec.AddAttributes(
		attribute.Int64("id", violation.ID),
		attribute.String("lastObservedTimestamp", violation.LastObservedTimestamp.UTC().Format(time.RFC3339)),
		attribute.String("reason", ack.Reason),
		attribute.String("policy.name", policyName),
		attribute.String("k8s.namespace.name", namespace),
		attribute.String("k8s.pod.name", violation.PodName),
		attribute.String("container.name", violation.ContainerName),
		attribute.String("proc.exepath", violation.ExecutablePath),
		attribute.String("node.name", violation.NodeName),
		attribute.String("action", violation.Action),
		attribute.String("workload.name", violation.WorkloadName),
		attribute.String("workload.kind", violation.WorkloadKind),
	)

	r.eventLogger.Emit(ctx, rec)
}
