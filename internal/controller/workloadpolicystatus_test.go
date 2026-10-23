package controller

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/kubewarden/runtime-enforcer/api/v1alpha1"
	"github.com/kubewarden/runtime-enforcer/internal/grpcexporter"
	"github.com/kubewarden/runtime-enforcer/internal/testutil"
	pb "github.com/kubewarden/runtime-enforcer/proto/agent/v1"
)

func testWPStatusSyncConfig(t *testing.T) *WorkloadPolicyStatusSyncConfig {
	t.Helper()
	return &WorkloadPolicyStatusSyncConfig{
		AgentPoolConf: grpcexporter.AgentClientPoolConfig{
			AgentFactoryConfig: grpcexporter.AgentFactoryConfig{
				Port:        50051,
				MTLSEnabled: false,
			},
			LabelSelectorString: "app=agent",
			Namespace:           "test-namespace",
			Logger:              testutil.NewTestLogger(t),
		},
		UpdateInterval: 1 * time.Second,
	}
}

func createTestWPStatusSync(t *testing.T) *WorkloadPolicyStatusSync {
	t.Helper()
	r, err := NewWorkloadPolicyStatusSync(newStatusSyncClient(t), testWPStatusSyncConfig(t))
	require.NoError(t, err)
	return r
}

type testAgentClient struct {
	policies         map[string]*pb.PolicyStatus
	violations       []*pb.ViolationRecord
	policiesErr      error
	scrapeErr        error
	listPoliciesFunc func(context.Context) (map[string]*pb.PolicyStatus, error)
	scrapeFunc       func(context.Context) ([]*pb.ViolationRecord, error)
}

func (c *testAgentClient) ListPoliciesStatus(ctx context.Context) (map[string]*pb.PolicyStatus, error) {
	if c.listPoliciesFunc != nil {
		return c.listPoliciesFunc(ctx)
	}
	return c.policies, c.policiesErr
}

func (c *testAgentClient) ListPodCache(_ context.Context) ([]*pb.PodView, error) {
	return nil, nil
}

func (c *testAgentClient) ScrapeViolations(ctx context.Context) ([]*pb.ViolationRecord, error) {
	if c.scrapeFunc != nil {
		return c.scrapeFunc(ctx)
	}
	return c.violations, c.scrapeErr
}

func (c *testAgentClient) Close() error {
	return nil
}

func TestGetViolationsByPolicy(t *testing.T) {
	ts := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	pbRec := func(policy, pod, node string) *pb.ViolationRecord {
		return &pb.ViolationRecord{
			Timestamp:      timestamppb.New(ts),
			PolicyName:     policy,
			PodName:        pod,
			ContainerName:  "c",
			ExecutablePath: "/usr/bin/test",
			NodeName:       node,
			Action:         "monitor",
		}
	}

	apiRec := func(pod, node string) v1alpha1.ViolationRecord {
		return v1alpha1.ViolationRecord{
			LastObservedTimestamp: metav1.NewTime(ts),
			PodName:               pod,
			ContainerName:         "c",
			ExecutablePath:        "/usr/bin/test",
			NodeName:              node,
			Action:                "monitor",
		}
	}

	t.Run("collects violations from healthy nodes", func(t *testing.T) {
		r := createTestWPStatusSync(t)

		client1 := &testAgentClient{
			violations: []*pb.ViolationRecord{
				pbRec("default/policy-a", "pod-1", "node1"),
			},
		}
		client2 := &testAgentClient{
			violations: []*pb.ViolationRecord{
				pbRec("default/policy-a", "pod-2", "node2"),
				pbRec("default/policy-b", "pod-3", "node2"),
			},
		}
		clients := map[string]grpcexporter.AgentClientAPI{
			"node1": client1,
			"node2": client2,
		}

		got := r.getViolationsByPolicy(context.Background(), clients)

		nnA := "default/policy-a"
		nnB := "default/policy-b"

		require.Len(t, got[nnA], 2)
		require.Contains(t, got[nnA], apiRec("pod-1", "node1"))
		require.Contains(t, got[nnA], apiRec("pod-2", "node2"))
		require.Equal(t, []v1alpha1.ViolationRecord{apiRec("pod-3", "node2")}, got[nnB])
	})

	t.Run("skips nodes without connection", func(t *testing.T) {
		r := createTestWPStatusSync(t)
		// No connections set up.

		clients := map[string]grpcexporter.AgentClientAPI{
			"node1": nil, // Simulate no connection to node1
		}

		got := r.getViolationsByPolicy(context.Background(), clients)
		require.Empty(t, got)
	})

	t.Run("skips node on scrape error", func(t *testing.T) {
		r := createTestWPStatusSync(t)
		pool := &testAgentClientPool{}
		r.agentClientPool = pool

		clients := map[string]grpcexporter.AgentClientAPI{
			"node1": &testAgentClient{scrapeErr: errors.New("connection refused")},
		}

		got := r.getViolationsByPolicy(context.Background(), clients)
		require.Empty(t, got)
		require.Equal(t, []string{"node1"}, pool.staleNodes)
	})

	t.Run("empty nodes returns empty map", func(t *testing.T) {
		r := createTestWPStatusSync(t)
		got := r.getViolationsByPolicy(context.Background(), nil)
		require.Empty(t, got)
	})
}
