package controller

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/attribute"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	"google.golang.org/protobuf/types/known/timestamppb"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	"github.com/kubewarden/runtime-enforcer/api/v1alpha1"
	"github.com/kubewarden/runtime-enforcer/internal/grpcexporter"
	pb "github.com/kubewarden/runtime-enforcer/proto/agent/v1"
)

func TestNewWorkloadPolicyStatusSyncPreservesConfig(t *testing.T) {
	config := testWPStatusSyncConfig(t)
	config.UpdateInterval = time.Minute
	logs := sdklog.NewLoggerProvider()
	metrics := sdkmetric.NewMeterProvider()
	t.Cleanup(func() {
		require.NoError(t, logs.Shutdown(context.Background()))
		require.NoError(t, metrics.Shutdown(context.Background()))
	})
	config.EventLogger = logs.Logger("status-sync")
	gauge, err := metrics.Meter("status-sync").Int64Gauge("active_violations")
	require.NoError(t, err)
	config.ActiveViolationsGauge = gauge
	c := newStatusSyncClient(t)
	r, err := NewWorkloadPolicyStatusSync(c, config)
	require.NoError(t, err)
	require.Same(t, c, r.Client)
	require.Same(t, config.EventLogger, r.eventLogger)
	require.Same(t, config.ActiveViolationsGauge, r.activeViolationsGauge)
	require.Equal(t, time.Minute, r.updateInterval)
}

func TestNewWorkloadPolicyStatusSyncRejectsInvalidConfig(t *testing.T) {
	tests := []struct {
		name   string
		change func(*WorkloadPolicyStatusSyncConfig)
		err    string
	}{
		{
			name: "zero interval", change: func(c *WorkloadPolicyStatusSyncConfig) { c.UpdateInterval = 0 },
			err: "invalid update interval",
		},
		{
			name:   "negative interval",
			change: func(c *WorkloadPolicyStatusSyncConfig) { c.UpdateInterval = -time.Second },
			err:    "invalid update interval",
		},
		{
			name:   "invalid selector",
			change: func(c *WorkloadPolicyStatusSyncConfig) { c.AgentPoolConf.LabelSelectorString = "app in (" },
			err:    "failed to create agent client pool",
		},
		{
			name: "invalid port", change: func(c *WorkloadPolicyStatusSyncConfig) { c.AgentPoolConf.Port = 0 },
			err: "invalid gRPC port",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := testWPStatusSyncConfig(t)
			tt.change(config)
			r, err := NewWorkloadPolicyStatusSync(newStatusSyncClient(t), config)
			require.ErrorContains(t, err, tt.err)
			require.Nil(t, r)
		})
	}
}

func TestWorkloadPolicyStatusSyncEarlyReturns(t *testing.T) {
	errUnavailable := errors.New("API unavailable")
	tests := []struct {
		name          string
		noPolicies    bool
		listErr       error
		poolErrorCall int
		wantPoolCalls int
	}{
		{name: "policy list failure", listErr: errUnavailable},
		{name: "no policies", noPolicies: true},
		{name: "initial pool failure", poolErrorCall: 1, wantPoolCalls: 1},
		{name: "refreshed pool failure", poolErrorCall: 2, wantPoolCalls: 2},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var objects []client.Object
			if !tt.noPolicies {
				objects = append(objects, statusSyncPolicy())
			}
			poolCalls, patches := 0, 0
			r := createTestWPStatusSync(t)
			r.Client = interceptor.NewClient(newStatusSyncClient(t, objects...), interceptor.Funcs{
				List: func(ctx context.Context, c client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
					if tt.listErr != nil {
						return tt.listErr
					}
					return c.List(ctx, list, opts...)
				},
				SubResourcePatch: func(context.Context, client.Client, string, client.Object,
					client.Patch, ...client.SubResourcePatchOption,
				) error {
					patches++
					return nil
				},
				Patch: func(context.Context, client.WithWatch, client.Object, client.Patch, ...client.PatchOption) error {
					patches++
					return nil
				},
			})
			r.agentClientPool = &testAgentClientPool{
				updateFunc: func(context.Context, client.Reader) (map[string]grpcexporter.AgentClientAPI, error) {
					poolCalls++
					if poolCalls == tt.poolErrorCall {
						return nil, errUnavailable
					}
					return map[string]grpcexporter.AgentClientAPI{}, nil
				},
			}
			err := r.sync(t.Context())
			if tt.noPolicies {
				require.NoError(t, err)
			} else {
				require.ErrorIs(t, err, errUnavailable)
			}
			require.Equal(t, tt.wantPoolCalls, poolCalls)
			require.Zero(t, patches)
		})
	}
}

func TestWorkloadPolicyStatusSyncPersistsAndRecordsMetrics(t *testing.T) {
	t.Run("healthy agent", func(t *testing.T) {
		testStatusSyncPersistsAndRecordsMetrics(t, false)
	})
	t.Run("reconnect before scraping", func(t *testing.T) {
		testStatusSyncPersistsAndRecordsMetrics(t, true)
	})
}

func testStatusSyncPersistsAndRecordsMetrics(t *testing.T, disconnected bool) {
	t.Helper()
	wp := statusSyncPolicy()
	other := &v1alpha1.WorkloadPolicy{
		Name: wp.Name, Namespace: "other", Generation: 2,
		Spec: v1alpha1.WorkloadPolicySpec{Mode: "monitor"},
	}
	failed := &v1alpha1.WorkloadPolicy{
		Name: "a-failing", Namespace: wp.Namespace, Generation: 1,
		Spec: v1alpha1.WorkloadPolicySpec{Mode: "protect"},
	}
	base := newStatusSyncClient(t, wp, other, failed)
	r := createTestWPStatusSync(t)
	var patches []string
	r.Client = interceptor.NewClient(base, interceptor.Funcs{
		List: func(ctx context.Context, c client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
			if err := c.List(ctx, list, opts...); err != nil {
				return err
			}
			policies, ok := list.(*v1alpha1.WorkloadPolicyList)
			require.True(t, ok)
			slices.SortFunc(policies.Items, func(a, b v1alpha1.WorkloadPolicy) int {
				return strings.Compare(a.NamespacedName(), b.NamespacedName())
			})
			return nil
		},
		SubResourcePatch: func(ctx context.Context, c client.Client, name string, obj client.Object,
			patch client.Patch, opts ...client.SubResourcePatchOption,
		) error {
			patches = append(patches, client.ObjectKeyFromObject(obj).String())
			if obj.GetName() == failed.Name {
				return errors.New("status write failed")
			}
			return c.SubResource(name).Patch(ctx, obj, patch, opts...)
		},
	})
	reader := sdkmetric.NewManualReader()
	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	t.Cleanup(func() { require.NoError(t, provider.Shutdown(context.Background())) })
	gauge, err := provider.Meter("test").Int64Gauge("active_violations")
	require.NoError(t, err)
	r.activeViolationsGauge = gauge

	type contextKey struct{}
	syncCtx, cancel := context.WithCancel(context.WithValue(t.Context(), contextKey{}, "sync"))
	defer cancel()
	var contexts []context.Context
	observeContext := func(ctx context.Context) {
		require.Equal(t, "sync", ctx.Value(contextKey{}))
		contexts = append(contexts, ctx)
	}
	var steps []string
	statuses := map[string]*pb.PolicyStatus{
		wp.NamespacedName():     {State: pb.PolicyState_POLICY_STATE_READY, Mode: pb.PolicyMode_POLICY_MODE_PROTECT},
		other.NamespacedName():  {State: pb.PolicyState_POLICY_STATE_ERROR, Message: "other policy map full"},
		failed.NamespacedName(): {State: pb.PolicyState_POLICY_STATE_READY, Mode: pb.PolicyMode_POLICY_MODE_PROTECT},
	}
	statusClient := &testAgentClient{
		listPoliciesFunc: func(ctx context.Context) (map[string]*pb.PolicyStatus, error) {
			observeContext(ctx)
			steps = append(steps, "statuses")
			if disconnected {
				return nil, errors.New("agent disconnected")
			}
			return statuses, nil
		},
	}
	ts := time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC)
	scrapeClient := &testAgentClient{
		scrapeFunc: func(ctx context.Context) ([]*pb.ViolationRecord, error) {
			observeContext(ctx)
			steps = append(steps, "violations")
			return []*pb.ViolationRecord{{
				PolicyName: wp.NamespacedName(), Timestamp: timestamppb.New(ts),
				PodName: "new-pod", ContainerName: "app", ExecutablePath: "/bin/new", NodeName: "node",
				Action: "protect", WorkloadName: "deployment", WorkloadKind: "Deployment",
			}}, nil
		},
	}
	poolCalls := 0
	pool := &testAgentClientPool{
		updateFunc: func(ctx context.Context, _ client.Reader) (map[string]grpcexporter.AgentClientAPI, error) {
			observeContext(ctx)
			steps = append(steps, "pool")
			poolCalls++
			if poolCalls == 1 {
				return map[string]grpcexporter.AgentClientAPI{"node": statusClient}, nil
			}
			return map[string]grpcexporter.AgentClientAPI{"node": scrapeClient}, nil
		},
	}
	r.agentClientPool = pool
	require.NoError(t, r.sync(syncCtx))
	cancel()
	for _, ctx := range contexts {
		require.ErrorIs(t, ctx.Err(), context.Canceled)
	}
	require.Equal(t, []string{"pool", "statuses", "pool", "violations"}, steps)
	require.Equal(t, []string{failed.NamespacedName(), wp.NamespacedName(), other.NamespacedName()}, patches)
	if disconnected {
		require.Equal(t, []string{"node"}, pool.staleNodes)
	} else {
		require.Empty(t, pool.staleNodes)
	}

	stored := &v1alpha1.WorkloadPolicy{}
	require.NoError(t, base.Get(t.Context(), client.ObjectKeyFromObject(wp), stored))
	require.Equal(t, wp.Generation, stored.Status.ObservedGeneration)
	require.Equal(t, 1, stored.Status.TotalNodes)
	if disconnected {
		require.Equal(t, v1alpha1.Failed, stored.Status.Phase)
		require.Equal(t, v1alpha1.PolicyMissing, stored.Status.NodesWithIssues["node"].Code)
	} else {
		require.Equal(t, v1alpha1.Ready, stored.Status.Phase)
		require.Equal(t, 1, stored.Status.SuccessfulNodes)
	}
	require.Equal(t, 1, stored.Status.ActiveViolationCount)
	require.Equal(t, int64(10), stored.Status.ViolationCount)
	require.Len(t, stored.Status.Violations, 1)
	violation := stored.Status.Violations[0]
	require.Equal(t, "new-pod", violation.PodName)
	require.Equal(t, "app", violation.ContainerName)
	require.Equal(t, "/bin/new", violation.ExecutablePath)
	require.Equal(t, "node", violation.NodeName)
	require.Equal(t, "protect", violation.Action)
	require.Equal(t, "deployment", violation.WorkloadName)
	require.Equal(t, "Deployment", violation.WorkloadKind)
	require.True(t, ts.Equal(violation.LastObservedTimestamp.Time))
	require.Len(t, stored.Status.AcknowledgedViolations, 1)
	require.NotContains(t, stored.Annotations, v1alpha1.ViolationAcknowledgePrefix+"7")
	require.NoError(t, base.Get(t.Context(), client.ObjectKeyFromObject(other), stored))
	require.Equal(t, other.Generation, stored.Status.ObservedGeneration)
	require.Empty(t, stored.Status.Violations)
	require.Equal(t, v1alpha1.Failed, stored.Status.Phase)
	require.Equal(t, 1, stored.Status.TotalNodes)
	require.Equal(t, 1, stored.Status.FailedNodes)
	if disconnected {
		require.Equal(t, v1alpha1.PolicyMissing, stored.Status.NodesWithIssues["node"].Code)
	} else {
		require.Equal(t, v1alpha1.PolicyFailed, stored.Status.NodesWithIssues["node"].Code)
		require.Equal(t, "other policy map full", stored.Status.NodesWithIssues["node"].Message)
	}
	require.NoError(t, base.Get(t.Context(), client.ObjectKeyFromObject(failed), stored))
	require.Equal(t, failed.Status, stored.Status)

	var metrics metricdata.ResourceMetrics
	require.NoError(t, reader.Collect(t.Context(), &metrics))
	require.Len(t, metrics.ScopeMetrics, 1)
	require.Len(t, metrics.ScopeMetrics[0].Metrics, 1)
	data, ok := metrics.ScopeMetrics[0].Metrics[0].Data.(metricdata.Gauge[int64])
	require.True(t, ok)
	require.Len(t, data.DataPoints, 2)
	values := map[string]int64{}
	for _, point := range data.DataPoints {
		policy, found := point.Attributes.Value(attribute.Key("policy.name"))
		require.True(t, found)
		namespace, found := point.Attributes.Value(attribute.Key("k8s.namespace.name"))
		require.True(t, found)
		require.Equal(t, 2, point.Attributes.Len())
		values[namespace.AsString()+"/"+policy.AsString()] = point.Value
	}
	require.Equal(t, map[string]int64{wp.NamespacedName(): 1, other.NamespacedName(): 0}, values)
}

func TestWorkloadPolicyStatusSyncKeepsUnreadyNodes(t *testing.T) {
	tests := []struct {
		name        string
		reported    *pb.PolicyStatus
		readyNodes  int
		wantCode    v1alpha1.PolicyCode
		wantMessage string
	}{
		{
			name: "missing on every node", wantCode: v1alpha1.PolicyMissing,
			wantMessage: "policy not found on the node",
		},
		{
			name: "missing on one node", readyNodes: 1, wantCode: v1alpha1.PolicyMissing,
			wantMessage: "policy not found on the node",
		},
		{
			name: "invalid state on one node", readyNodes: 1,
			reported: &pb.PolicyStatus{State: pb.PolicyState(99)}, wantCode: v1alpha1.PolicyFailed,
			wantMessage: `unknown policy state "99"`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pending := &v1alpha1.WorkloadPolicy{
				Name: "pending", Namespace: "default", Spec: v1alpha1.WorkloadPolicySpec{Mode: "protect"},
			}
			loaded := &v1alpha1.WorkloadPolicy{
				Name: "loaded", Namespace: "default", Spec: v1alpha1.WorkloadPolicySpec{Mode: "protect"},
			}
			ready := &pb.PolicyStatus{State: pb.PolicyState_POLICY_STATE_READY, Mode: pb.PolicyMode_POLICY_MODE_PROTECT}
			lagging := map[string]*pb.PolicyStatus{loaded.NamespacedName(): ready}
			if tt.reported != nil {
				lagging[pending.NamespacedName()] = tt.reported
			}
			clients := map[string]grpcexporter.AgentClientAPI{
				"lagging": &testAgentClient{policies: lagging},
			}
			if tt.readyNodes > 0 {
				clients["ready"] = &testAgentClient{policies: map[string]*pb.PolicyStatus{
					loaded.NamespacedName(): ready, pending.NamespacedName(): ready,
				}}
			}
			r := createTestWPStatusSync(t)
			r.Client = newStatusSyncClient(t, pending, loaded)
			r.agentClientPool = &testAgentClientPool{clients: clients}
			require.NoError(t, r.sync(t.Context()))
			stored := &v1alpha1.WorkloadPolicy{}
			require.NoError(t, r.Get(t.Context(), client.ObjectKeyFromObject(pending), stored))
			require.Equal(t, v1alpha1.Failed, stored.Status.Phase)
			require.Equal(t, len(clients), stored.Status.TotalNodes)
			require.Equal(t, tt.readyNodes, stored.Status.SuccessfulNodes)
			require.Equal(t, 1, stored.Status.FailedNodes)
			require.Len(t, stored.Status.NodesWithIssues, 1)
			require.Equal(t, tt.wantCode, stored.Status.NodesWithIssues["lagging"].Code)
			require.Equal(t, tt.wantMessage, stored.Status.NodesWithIssues["lagging"].Message)
			require.NoError(t, r.Get(t.Context(), client.ObjectKeyFromObject(loaded), stored))
			require.Equal(t, v1alpha1.Ready, stored.Status.Phase)
			require.Equal(t, len(clients), stored.Status.SuccessfulNodes)
			require.Empty(t, stored.Status.NodesWithIssues)
		})
	}
}

func TestWorkloadPolicyStatusSyncStart(t *testing.T) {
	t.Run("already canceled", func(t *testing.T) {
		r := createTestWPStatusSync(t)
		r.updateInterval = time.Hour
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		require.NoError(t, r.Start(ctx))
	})

	t.Run("retries failed sync and stops on cancellation", func(t *testing.T) {
		r := createTestWPStatusSync(t)
		r.updateInterval = time.Millisecond
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		defer cancel()
		calls := 0
		r.Client = interceptor.NewClient(newStatusSyncClient(t), interceptor.Funcs{
			List: func(ctx context.Context, c client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
				calls++
				if calls == 1 {
					return errors.New("temporary API failure")
				}
				err := c.List(ctx, list, opts...)
				cancel()
				return err
			},
		})
		require.NoError(t, r.Start(ctx))
		require.GreaterOrEqual(t, calls, 2)
		require.ErrorIs(t, ctx.Err(), context.Canceled)
	})
}
