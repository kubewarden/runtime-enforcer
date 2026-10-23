package controller

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/attribute"
	otellog "go.opentelemetry.io/otel/log"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	"github.com/kubewarden/runtime-enforcer/api/v1alpha1"
	"github.com/kubewarden/runtime-enforcer/internal/grpcexporter"
	pb "github.com/kubewarden/runtime-enforcer/proto/agent/v1"
)

func TestPolicyNodeStatus(t *testing.T) {
	tests := []struct {
		name         string
		expectedMode string
		status       *pb.PolicyStatus
		code         v1alpha1.PolicyCode
		message      string
		err          string
	}{
		{
			name: "monitor ready", expectedMode: "monitor",
			status: &pb.PolicyStatus{State: pb.PolicyState_POLICY_STATE_READY, Mode: pb.PolicyMode_POLICY_MODE_MONITOR},
			code:   v1alpha1.PolicyReady,
		},
		{
			name: "protect ready", expectedMode: "protect",
			status: &pb.PolicyStatus{State: pb.PolicyState_POLICY_STATE_READY, Mode: pb.PolicyMode_POLICY_MODE_PROTECT},
			code:   v1alpha1.PolicyReady,
		},
		{
			name: "transition to protect", expectedMode: "protect",
			status: &pb.PolicyStatus{State: pb.PolicyState_POLICY_STATE_READY, Mode: pb.PolicyMode_POLICY_MODE_MONITOR},
			code:   v1alpha1.PolicyTransitioning,
		},
		{
			name: "transition to monitor", expectedMode: "monitor",
			status: &pb.PolicyStatus{State: pb.PolicyState_POLICY_STATE_READY, Mode: pb.PolicyMode_POLICY_MODE_PROTECT},
			code:   v1alpha1.PolicyTransitioning,
		},
		{
			name: "unspecified agent mode", expectedMode: "protect",
			status: &pb.PolicyStatus{State: pb.PolicyState_POLICY_STATE_READY},
			code:   v1alpha1.PolicyTransitioning,
		},
		{
			name: "unsupported expected mode", expectedMode: "invalid",
			status: &pb.PolicyStatus{State: pb.PolicyState_POLICY_STATE_READY, Mode: pb.PolicyMode_POLICY_MODE_PROTECT},
			code:   v1alpha1.PolicyTransitioning,
		},
		{
			name:   "error with message",
			status: &pb.PolicyStatus{State: pb.PolicyState_POLICY_STATE_ERROR, Message: "map update failed"},
			code:   v1alpha1.PolicyFailed, message: "map update failed",
		},
		{
			name:   "error without message",
			status: &pb.PolicyStatus{State: pb.PolicyState_POLICY_STATE_ERROR},
			code:   v1alpha1.PolicyFailed, message: "policy is in error state",
		},
		{name: "missing status", code: v1alpha1.PolicyMissing, message: "policy not found on the node"},
		{
			name: "unspecified state", status: &pb.PolicyStatus{},
			code: v1alpha1.PolicyUnknown, err: "unknown policy state",
		},
		{
			name: "unknown state", status: &pb.PolicyStatus{State: pb.PolicyState(99)},
			code: v1alpha1.PolicyUnknown, err: "unknown policy state",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, message, err := policyNodeStatus(tt.expectedMode, tt.status)
			if tt.err != "" {
				require.ErrorContains(t, err, tt.err)
			} else {
				require.NoError(t, err)
			}
			require.Equal(t, tt.code, code)
			require.Equal(t, tt.message, message)
		})
	}
}

func TestGetNodeStatusByPolicy(t *testing.T) {
	r := createTestWPStatusSync(t)
	pool := &testAgentClientPool{}
	r.agentClientPool = pool
	policies := []v1alpha1.WorkloadPolicy{
		{Name: "policy", Namespace: "one", Spec: v1alpha1.WorkloadPolicySpec{Mode: "protect"}},
		{Name: "policy", Namespace: "two", Spec: v1alpha1.WorkloadPolicySpec{Mode: "monitor"}},
	}
	clients := map[string]grpcexporter.AgentClientAPI{
		"ready": &testAgentClient{policies: map[string]*pb.PolicyStatus{
			"one/policy": {State: pb.PolicyState_POLICY_STATE_READY, Mode: pb.PolicyMode_POLICY_MODE_PROTECT},
			"two/policy": {State: pb.PolicyState_POLICY_STATE_READY, Mode: pb.PolicyMode_POLICY_MODE_MONITOR},
		}},
		"transitioning": &testAgentClient{policies: map[string]*pb.PolicyStatus{
			"one/policy": {State: pb.PolicyState_POLICY_STATE_READY, Mode: pb.PolicyMode_POLICY_MODE_MONITOR},
			"two/policy": {State: pb.PolicyState_POLICY_STATE_READY, Mode: pb.PolicyMode_POLICY_MODE_PROTECT},
		}},
		"failed": &testAgentClient{policies: map[string]*pb.PolicyStatus{
			"one/policy": {State: pb.PolicyState_POLICY_STATE_ERROR, Message: "map full"},
			"two/policy": {State: pb.PolicyState_POLICY_STATE_ERROR, Message: "map full"},
		}},
		"partial": &testAgentClient{policies: map[string]*pb.PolicyStatus{
			"two/policy": {State: pb.PolicyState_POLICY_STATE_READY, Mode: pb.PolicyMode_POLICY_MODE_MONITOR},
		}},
		"invalid": &testAgentClient{policies: map[string]*pb.PolicyStatus{
			"one/policy": {State: pb.PolicyState(99)},
			"two/policy": {},
		}},
		"unavailable": nil,
		"empty":       &testAgentClient{},
		"disconnected": &testAgentClient{
			policiesErr: errors.New("connection refused"),
		},
	}
	got := r.getNodeStatusByPolicy(t.Context(), clients, policies)
	require.Len(t, got, 2)
	for _, policy := range policies {
		partial := v1alpha1.PolicyNodeStatus{
			NodeName: "partial", Code: v1alpha1.PolicyMissing, Message: "policy not found on the node",
		}
		invalidMessage := `unknown policy state "99"`
		if policy.Namespace == "two" {
			partial.Code = v1alpha1.PolicyReady
			partial.Message = ""
			invalidMessage = `unknown policy state "POLICY_STATE_UNSPECIFIED"`
		}
		require.ElementsMatch(t, []v1alpha1.PolicyNodeStatus{
			{NodeName: "ready", Code: v1alpha1.PolicyReady},
			{NodeName: "transitioning", Code: v1alpha1.PolicyTransitioning},
			{NodeName: "failed", Code: v1alpha1.PolicyFailed, Message: "map full"},
			{NodeName: "unavailable", Code: v1alpha1.PolicyMissing, Message: "No agent client available"},
			{NodeName: "empty", Code: v1alpha1.PolicyMissing, Message: "no policies found on the node"},
			{NodeName: "disconnected", Code: v1alpha1.PolicyMissing, Message: "failed to get policies status"},
			partial,
			{NodeName: "invalid", Code: v1alpha1.PolicyFailed, Message: invalidMessage},
		}, got[policy.NamespacedName()])
	}
	require.Equal(t, []string{"disconnected"}, pool.staleNodes)

	got = r.getNodeStatusByPolicy(t.Context(), nil, policies)
	require.Len(t, got, len(policies))
	for _, policy := range policies {
		require.Contains(t, got, policy.NamespacedName())
		require.Empty(t, got[policy.NamespacedName()])
	}
}

func TestProcessWorkloadPolicyPersistsBeforeAcknowledging(t *testing.T) {
	wp := statusSyncPolicy()
	base := newStatusSyncClient(t, wp)
	require.NoError(t, base.Get(t.Context(), client.ObjectKeyFromObject(wp), wp))
	original := wp.DeepCopy()
	r := createTestWPStatusSync(t)
	exporter := recordStatusSyncLogs(t, r)
	var steps []string
	exporter.onExport = func() {
		stored := &v1alpha1.WorkloadPolicy{}
		require.NoError(t, base.Get(t.Context(), client.ObjectKeyFromObject(wp), stored))
		require.Len(t, stored.Status.AcknowledgedViolations, 1)
		require.Equal(t, "investigated", stored.Annotations[v1alpha1.ViolationAcknowledgePrefix+"7"])
		steps = append(steps, "log")
	}
	r.Client = interceptor.NewClient(base, interceptor.Funcs{
		SubResourcePatch: func(ctx context.Context, c client.Client, subresource string, obj client.Object,
			patch client.Patch, opts ...client.SubResourcePatchOption,
		) error {
			require.Equal(t, "status", subresource)
			require.Empty(t, steps)
			err := c.SubResource(subresource).Patch(ctx, obj, patch, opts...)
			steps = append(steps, "status")
			return err
		},
		Patch: func(ctx context.Context, c client.WithWatch, obj client.Object,
			patch client.Patch, opts ...client.PatchOption,
		) error {
			require.Equal(t, []string{"status", "log"}, steps)
			concurrent := &v1alpha1.WorkloadPolicy{}
			require.NoError(t, c.Get(ctx, client.ObjectKeyFromObject(wp), concurrent))
			concurrent.Annotations["concurrent"] = "retained"
			require.NoError(t, c.Update(ctx, concurrent))
			steps = append(steps, "metadata")
			return c.Patch(ctx, obj, patch, opts...)
		},
	})
	nodes := []v1alpha1.PolicyNodeStatus{
		{NodeName: "node", Code: v1alpha1.PolicyReady},
		{NodeName: "failed", Code: v1alpha1.PolicyFailed, Message: "map full"},
	}
	scraped := original.Status.Violations[0]
	scraped.ExecutablePath = "/bin/new"
	before := time.Now()
	require.NoError(t, r.processWorkloadPolicy(t.Context(), wp, nodes, []v1alpha1.ViolationRecord{scraped}))
	after := time.Now()
	require.Equal(t, []string{"status", "log", "metadata"}, steps)
	require.Equal(t, original.Spec, wp.Spec)
	require.Equal(t, int64(10), wp.Status.ViolationCount)
	require.Equal(t, 1, wp.Status.ActiveViolationCount)
	require.Equal(t, wp.Generation, wp.Status.ObservedGeneration)
	require.Equal(t, v1alpha1.Failed, wp.Status.Phase)
	require.Equal(t, 2, wp.Status.TotalNodes)
	require.Equal(t, 1, wp.Status.SuccessfulNodes)
	require.Equal(t, 1, wp.Status.FailedNodes)
	require.Equal(t, "map full", wp.Status.NodesWithIssues["failed"].Message)
	require.Len(t, wp.Status.Violations, 1)
	require.Equal(t, "/bin/new", wp.Status.Violations[0].ExecutablePath)
	require.Equal(t, int64(9), wp.Status.Violations[0].ID)
	require.Len(t, wp.Status.AcknowledgedViolations, 1)
	require.Equal(t, original.Status.Violations[0], wp.Status.AcknowledgedViolations[0].Violation)
	require.Equal(t, "investigated", wp.Status.AcknowledgedViolations[0].Reason)
	require.False(t, wp.Status.AcknowledgedViolations[0].AcknowledgedAt.Time.Before(before))
	require.False(t, wp.Status.AcknowledgedViolations[0].AcknowledgedAt.Time.After(after))
	require.NotContains(t, wp.Annotations, v1alpha1.ViolationAcknowledgePrefix+"7")
	require.Equal(t, "preserved", wp.Annotations["unrelated"])

	stored := &v1alpha1.WorkloadPolicy{}
	require.NoError(t, base.Get(t.Context(), client.ObjectKeyFromObject(wp), stored))
	require.Equal(t, wp.Spec, stored.Spec)
	require.Equal(t, wp.Status.Violations, stored.Status.Violations)
	require.Equal(t, wp.Status.ActiveViolationCount, stored.Status.ActiveViolationCount)
	require.Equal(t, int64(10), stored.Status.ViolationCount)
	require.Equal(t, map[string]string{"unrelated": "preserved", "concurrent": "retained"}, stored.Annotations)

	require.Len(t, exporter.records, 1)
	record := exporter.records[0]
	require.Equal(t, "policy_violation_acknowledged", record.EventName())
	require.Equal(t, otellog.SeverityInfo, record.Severity())
	require.Equal(t, "policy_violation_acknowledged", record.Body().AsString())
	require.False(t, record.Timestamp().Before(before))
	require.False(t, record.Timestamp().After(after))
	attributes := map[string]any{}
	record.WalkAttributes(func(kv attribute.KeyValue) bool {
		attributes[string(kv.Key)] = kv.Value.AsInterface()
		return true
	})
	require.Equal(t, map[string]any{
		"id": int64(7), "lastObservedTimestamp": "2026-01-01T12:00:00Z", "reason": "investigated",
		"policy.name": "policy", "k8s.namespace.name": "default", "k8s.pod.name": "pod",
		"container.name": "app", "proc.exepath": "/bin/blocked", "node.name": "node",
		"action": "protect", "workload.name": "deployment", "workload.kind": "Deployment",
	}, attributes)
}

func TestProcessWorkloadPolicyFailures(t *testing.T) {
	resource := schema.GroupResource{Group: "runtimeenforcer.kubewarden.io", Resource: "workloadpolicies"}
	conflict := apierrors.NewConflict(resource, "policy", errors.New("changed concurrently"))
	notFound := apierrors.NewNotFound(resource, "policy")
	tests := []struct {
		name         string
		invalidNode  bool
		statusErr    error
		metadataErr  error
		wantErr      error
		wantSteps    []string
		wantLogCount int
	}{
		{name: "invalid node status", invalidNode: true},
		{name: "status conflict", statusErr: conflict, wantErr: conflict, wantSteps: []string{"status"}},
		{name: "status deleted", statusErr: notFound, wantSteps: []string{"status"}},
		{
			name: "metadata conflict", metadataErr: conflict, wantErr: conflict,
			wantSteps: []string{"status", "metadata"}, wantLogCount: 1,
		},
		{
			name: "metadata deleted", metadataErr: notFound,
			wantSteps: []string{"status", "metadata"}, wantLogCount: 1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wp := statusSyncPolicy()
			base := newStatusSyncClient(t, wp)
			require.NoError(t, base.Get(t.Context(), client.ObjectKeyFromObject(wp), wp))
			original := wp.DeepCopy()
			r := createTestWPStatusSync(t)
			exporter := recordStatusSyncLogs(t, r)
			var steps []string
			r.Client = interceptor.NewClient(base, interceptor.Funcs{
				SubResourcePatch: func(ctx context.Context, c client.Client, name string, obj client.Object,
					patch client.Patch, opts ...client.SubResourcePatchOption,
				) error {
					steps = append(steps, "status")
					if tt.statusErr != nil {
						return tt.statusErr
					}
					return c.SubResource(name).Patch(ctx, obj, patch, opts...)
				},
				Patch: func(context.Context, client.WithWatch, client.Object, client.Patch, ...client.PatchOption) error {
					steps = append(steps, "metadata")
					return tt.metadataErr
				},
			})
			nodes := []v1alpha1.PolicyNodeStatus{{NodeName: "node", Code: v1alpha1.PolicyReady}}
			if tt.invalidNode {
				nodes[0].Code = v1alpha1.PolicyUnknown
			}
			err := r.processWorkloadPolicy(t.Context(), wp, nodes, nil)
			switch {
			case tt.invalidNode:
				require.ErrorContains(t, err, "unknown node status")
			case tt.wantErr != nil:
				require.ErrorIs(t, err, tt.wantErr)
				require.ErrorContains(t, err, "default/policy")
			default:
				require.NoError(t, err)
			}
			require.Equal(t, original, wp)
			require.Equal(t, tt.wantSteps, steps)
			require.Len(t, exporter.records, tt.wantLogCount)
			stored := &v1alpha1.WorkloadPolicy{}
			require.NoError(t, base.Get(t.Context(), client.ObjectKeyFromObject(wp), stored))
			require.Equal(t, original.Annotations, stored.Annotations)
			if tt.wantLogCount == 0 {
				require.Equal(t, original.Status, stored.Status)
			} else {
				require.Len(t, stored.Status.AcknowledgedViolations, 1)
				require.Empty(t, stored.Status.Violations)
			}
		})
	}
}

func TestProcessWorkloadPolicyRetriesStatusConflict(t *testing.T) {
	wp := statusSyncPolicy()
	base := newStatusSyncClient(t, wp)
	r := createTestWPStatusSync(t)
	exporter := recordStatusSyncLogs(t, r)
	attempts := 0
	conflict := apierrors.NewConflict(
		schema.GroupResource{Resource: "workloadpolicies"},
		wp.Name,
		errors.New("conflict"),
	)
	r.Client = interceptor.NewClient(base, interceptor.Funcs{
		SubResourcePatch: func(ctx context.Context, c client.Client, name string, obj client.Object,
			patch client.Patch, opts ...client.SubResourcePatchOption,
		) error {
			attempts++
			if attempts == 1 {
				return conflict
			}
			return c.SubResource(name).Patch(ctx, obj, patch, opts...)
		},
	})
	nodes := []v1alpha1.PolicyNodeStatus{{NodeName: "node", Code: v1alpha1.PolicyReady}}
	require.NoError(t, base.Get(t.Context(), client.ObjectKeyFromObject(wp), wp))
	require.ErrorIs(t, r.processWorkloadPolicy(t.Context(), wp, nodes, nil), conflict)
	require.Empty(t, exporter.records)
	for range 2 {
		require.NoError(t, base.Get(t.Context(), client.ObjectKeyFromObject(wp), wp))
		require.NoError(t, r.processWorkloadPolicy(t.Context(), wp, nodes, nil))
	}
	require.NoError(t, base.Get(t.Context(), client.ObjectKeyFromObject(wp), wp))
	require.Len(t, exporter.records, 1)
	require.Len(t, wp.Status.AcknowledgedViolations, 1)
	require.NotContains(t, wp.Annotations, v1alpha1.ViolationAcknowledgePrefix+"7")
}

func TestProcessWorkloadPolicyMetadataRetryDoesNotDuplicateAcknowledgement(t *testing.T) {
	wp := statusSyncPolicy()
	base := newStatusSyncClient(t, wp)
	r := createTestWPStatusSync(t)
	exporter := recordStatusSyncLogs(t, r)
	attempts := 0
	errUnavailable := errors.New("API unavailable")
	r.Client = interceptor.NewClient(base, interceptor.Funcs{
		Patch: func(ctx context.Context, c client.WithWatch, obj client.Object,
			patch client.Patch, opts ...client.PatchOption,
		) error {
			attempts++
			if attempts == 1 {
				return errUnavailable
			}
			return c.Patch(ctx, obj, patch, opts...)
		},
	})
	nodes := []v1alpha1.PolicyNodeStatus{{NodeName: "node", Code: v1alpha1.PolicyReady}}
	require.NoError(t, base.Get(t.Context(), client.ObjectKeyFromObject(wp), wp))
	require.ErrorIs(t, r.processWorkloadPolicy(t.Context(), wp, nodes, nil), errUnavailable)
	require.Len(t, exporter.records, 1)
	require.NoError(t, base.Get(t.Context(), client.ObjectKeyFromObject(wp), wp))
	require.Len(t, wp.Status.AcknowledgedViolations, 1)
	acknowledged := wp.Status.AcknowledgedViolations[0]
	require.Contains(t, wp.Annotations, v1alpha1.ViolationAcknowledgePrefix+"7")
	require.NoError(t, r.processWorkloadPolicy(t.Context(), wp, nodes, nil))
	require.NoError(t, base.Get(t.Context(), client.ObjectKeyFromObject(wp), wp))
	require.Len(t, exporter.records, 1)
	require.Equal(t, []v1alpha1.AcknowledgedViolationRecord{acknowledged}, wp.Status.AcknowledgedViolations)
	require.Empty(t, wp.Status.Violations)
}
