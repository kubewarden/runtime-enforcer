package controller

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/kubewarden/runtime-enforcer/api/v1alpha1"
	"github.com/kubewarden/runtime-enforcer/internal/grpcexporter"
	"github.com/kubewarden/runtime-enforcer/internal/testutil"
	pb "github.com/kubewarden/runtime-enforcer/proto/agent/v1"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func createTestWPStatusSync(t *testing.T) *WorkloadPolicyStatusSync {
	scheme := runtime.NewScheme()
	corev1.AddToScheme(scheme)
	v1alpha1.AddToScheme(scheme)
	cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects().Build()
	config := &WorkloadPolicyStatusSyncConfig{
		AgentPoolConf: grpcexporter.AgentClientPoolConfig{
			AgentFactoryConfig: grpcexporter.AgentFactoryConfig{
				Port:        50051,
				MTLSEnabled: false,
			},
			LabelSelectorString: "app=agent",
			// We explicitly provide a namespace so that this is not computed at runtime.
			Namespace: "test-namespace",
			Logger:    testutil.NewTestLogger(t),
		},
		UpdateInterval: 1 * time.Second,
	}

	r, err := NewWorkloadPolicyStatusSync(cl, config)
	require.NoError(t, err)
	return r
}

type testAgentClient struct {
	policies   map[string]*pb.PolicyStatus
	violations []*pb.ViolationRecord
	scrapeErr  error
}

func (c *testAgentClient) ListPoliciesStatus(_ context.Context) (map[string]*pb.PolicyStatus, error) {
	return c.policies, nil
}

func (c *testAgentClient) ListPodCache(_ context.Context) ([]*pb.PodView, error) {
	return nil, nil
}

func (c *testAgentClient) ScrapeViolations(_ context.Context) ([]*pb.ViolationRecord, error) {
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

		clients := map[string]grpcexporter.AgentClientAPI{
			"node1": &testAgentClient{scrapeErr: errors.New("connection refused")},
		}

		got := r.getViolationsByPolicy(context.Background(), clients)
		require.Empty(t, got)
	})

	t.Run("empty nodes returns empty map", func(t *testing.T) {
		r := createTestWPStatusSync(t)
		got := r.getViolationsByPolicy(context.Background(), nil)
		require.Empty(t, got)
	})
}
