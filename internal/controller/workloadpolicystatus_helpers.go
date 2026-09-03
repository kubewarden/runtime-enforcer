package controller

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/kubewarden/runtime-enforcer/api/v1alpha1"
	"github.com/kubewarden/runtime-enforcer/internal/grpcexporter"
	"github.com/kubewarden/runtime-enforcer/internal/types/loglevel"
	"github.com/kubewarden/runtime-enforcer/internal/types/policymode"
	pb "github.com/kubewarden/runtime-enforcer/proto/agent/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func (r *WorkloadPolicyStatusSync) managePatchError(err error, policyNamespacedName string, msg string) error {
	if apierrors.IsNotFound(err) {
		r.logger.Info(msg,
			"policy", policyNamespacedName)
		return nil
	}
	return fmt.Errorf("%s %q: %w", msg, policyNamespacedName, err)
}

// processWorkloadPolicy updates the wp.status and wp.annotation in order to acknowledge a violation.
// On success, *wp is replaced with the patched policy. On failure, *wp is left unchanged.
// NOTE: agent side ignores annotation changes and status change via predicate.GenerationChangedPredicate{}.
func (r *WorkloadPolicyStatusSync) processWorkloadPolicy(
	ctx context.Context,
	wp *v1alpha1.WorkloadPolicy,
	nodes []v1alpha1.PolicyNodeStatus,
	scrapedViolations []v1alpha1.ViolationRecord,
) error {
	patchBase := client.MergeFrom(wp.DeepCopy())
	newPolicy := wp.DeepCopy()
	policyNamespacedName := newPolicy.NamespacedName()

	acknowledged, err := newPolicy.RecomputeStatus(nodes, scrapedViolations, time.Now())
	if err != nil {
		return err
	}

	r.logger.V(loglevel.VerbosityDebug).Info("updating",
		"policy", policyNamespacedName,
		"annotations", newPolicy.Annotations,
		"status", newPolicy.Status)

	// At this point, we already have the expected WorkloadPolicy.
	// Due to kubernetes design, we have to call update annotations and status separately.
	// Here we use Patch() to prevent annotation changes made between two calls from being lost.

	// We update status first and remove the annotations later
	// If anything goes wrong we can retry in the next reconcile.
	err = r.Status().Patch(ctx, newPolicy.DeepCopy(), patchBase)
	if err != nil {
		return r.managePatchError(err, policyNamespacedName, "failed to update status for policy")
	}

	// Only if the status update was successful we emit the logs.
	// In this way we won't send duplicate logs in case of retries
	for _, ack := range acknowledged {
		r.emitAcknowledgedViolationOtelLog(ctx, newPolicy.Name, newPolicy.Namespace, ack)
	}

	err = r.Patch(ctx, newPolicy.DeepCopy(), patchBase)
	if err != nil {
		return r.managePatchError(err, policyNamespacedName, "failed to patch the policy")
	}
	*wp = *newPolicy
	return nil
}

func storeStatusForEachPolicy(
	nodeStatusByPolicy map[string][]v1alpha1.PolicyNodeStatus,
	policies []v1alpha1.WorkloadPolicy,
	nodeStatus v1alpha1.PolicyNodeStatus,
) {
	// Store the node status for the given policy
	for _, policy := range policies {
		policyNamespacedName := policy.NamespacedName()
		nodeStatusByPolicy[policyNamespacedName] = append(
			nodeStatusByPolicy[policyNamespacedName],
			nodeStatus,
		)
	}
}

func (r *WorkloadPolicyStatusSync) getNodeStatusByPolicy(
	ctx context.Context,
	clients map[string]grpcexporter.AgentClientAPI,
	policies []v1alpha1.WorkloadPolicy,
) map[string][]v1alpha1.PolicyNodeStatus {
	nodeStatusByPolicy := make(map[string][]v1alpha1.PolicyNodeStatus, len(policies))
	for _, policy := range policies {
		nodeStatusByPolicy[policy.NamespacedName()] = make([]v1alpha1.PolicyNodeStatus, 0, len(clients))
	}

	for nodeName, client := range clients {
		if client == nil {
			r.logger.Info("cannot get a agent client for the node", "node", nodeName)
			storeStatusForEachPolicy(nodeStatusByPolicy, policies, v1alpha1.PolicyNodeStatus{
				NodeName: nodeName,
				Code:     v1alpha1.PolicyMissing,
				Message:  "No agent client available",
			})
			continue
		}

		nodePolicies, err := client.ListPoliciesStatus(ctx)
		if err != nil {
			r.agentClientPool.MarkStaleAgentClient(nodeName)
			r.logger.Error(err, "failed to get policies status", "node", nodeName)
			storeStatusForEachPolicy(nodeStatusByPolicy, policies, v1alpha1.PolicyNodeStatus{
				NodeName: nodeName,
				Code:     v1alpha1.PolicyMissing,
				Message:  "failed to get policies status",
			})
			continue
		}

		if len(nodePolicies) == 0 {
			r.logger.Error(errors.New("empty policy list"), "No policies found", "node", nodeName)
			storeStatusForEachPolicy(nodeStatusByPolicy, policies, v1alpha1.PolicyNodeStatus{
				NodeName: nodeName,
				Code:     v1alpha1.PolicyMissing,
				Message:  "no policies found on the node",
			})
			continue
		}

		for _, policy := range policies {
			policyNamespacedName := policy.NamespacedName()
			nodeStatus := v1alpha1.PolicyNodeStatus{NodeName: nodeName}

			if nodeStatus.Code, nodeStatus.Message, err = policyNodeStatus(
				policy.Spec.Mode,
				nodePolicies[policyNamespacedName],
			); err != nil {
				r.logger.Error(
					err,
					"failed to get policy node status",
					"node",
					nodeName,
					"policy",
					policyNamespacedName,
				)
				continue
			}

			nodeStatusByPolicy[policyNamespacedName] = append(
				nodeStatusByPolicy[policyNamespacedName],
				nodeStatus,
			)
		}
	}

	return nodeStatusByPolicy
}

func policyNodeStatus(
	expectedMode string,
	policyStatus *pb.PolicyStatus,
) (v1alpha1.PolicyCode, string, error) {
	if policyStatus == nil {
		return v1alpha1.PolicyUnknown, "", errors.New("policy status is nil")
	}

	policyModeMatchesExpected := func(mode pb.PolicyMode, expectedMode string) bool {
		switch expectedMode {
		case policymode.ProtectString:
			return mode == pb.PolicyMode_POLICY_MODE_PROTECT
		case policymode.MonitorString:
			return mode == pb.PolicyMode_POLICY_MODE_MONITOR
		default:
			return false
		}
	}

	switch policyStatus.GetState() {
	case pb.PolicyState_POLICY_STATE_READY:
		if policyModeMatchesExpected(policyStatus.GetMode(), expectedMode) {
			return v1alpha1.PolicyReady, "", nil
		}
		return v1alpha1.PolicyTransitioning, "", nil
	case pb.PolicyState_POLICY_STATE_ERROR:
		msg := policyStatus.GetMessage()
		if msg == "" {
			msg = "policy is in error state"
		}
		return v1alpha1.PolicyFailed, msg, nil
	case pb.PolicyState_POLICY_STATE_UNSPECIFIED:
		fallthrough
	default:
		return v1alpha1.PolicyUnknown, "", fmt.Errorf("unknown policy state %q",
			policyStatus.GetState().String())
	}
}
