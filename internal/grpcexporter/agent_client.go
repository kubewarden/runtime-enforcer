package grpcexporter

import (
	"context"
	"time"

	pb "github.com/kubewarden/runtime-enforcer/proto/agent/v1"
	"google.golang.org/grpc"
)

const (
	agentClientTimeout = 30 * time.Second
)

// AgentClientAPI this interface could be used to mock clients in tests.
type AgentClientAPI interface {
	ListPoliciesStatus(ctx context.Context) (map[string]*pb.PolicyStatus, error)
	ScrapeViolations(ctx context.Context) ([]*pb.ViolationRecord, error)
	ListPodCache(ctx context.Context) ([]*pb.PodView, error)
	Close() error
}

// AgentClient is the implementation of AgentClientAPI used in the production code.
type AgentClient struct {
	conn    *grpc.ClientConn
	client  pb.AgentObserverClient
	timeout time.Duration
}

func (c *AgentClient) ListPoliciesStatus(ctx context.Context) (map[string]*pb.PolicyStatus, error) {
	timeoutCtx, timeoutCancel := context.WithTimeout(ctx, c.timeout)
	defer timeoutCancel()

	resp, err := c.client.ListPoliciesStatus(timeoutCtx, &pb.ListPoliciesStatusRequest{})
	if err != nil {
		return nil, err
	}
	return resp.GetPolicies(), nil
}

func (c *AgentClient) ScrapeViolations(ctx context.Context) ([]*pb.ViolationRecord, error) {
	timeoutCtx, timeoutCancel := context.WithTimeout(ctx, c.timeout)
	defer timeoutCancel()

	resp, err := c.client.ScrapeViolations(timeoutCtx, &pb.ScrapeViolationsRequest{})
	if err != nil {
		return nil, err
	}
	return resp.GetViolations(), nil
}

func (c *AgentClient) ListPodCache(ctx context.Context) ([]*pb.PodView, error) {
	timeoutCtx, timeoutCancel := context.WithTimeout(ctx, c.timeout)
	defer timeoutCancel()

	resp, err := c.client.ListPodCache(timeoutCtx, &pb.ListPodCacheRequest{})
	if err != nil {
		return nil, err
	}
	return resp.GetPods(), nil
}

func (c *AgentClient) Close() error {
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}
