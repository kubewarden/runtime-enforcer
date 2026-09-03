package grpcexporter

import (
	"context"

	"log/slog"

	"github.com/kubewarden/runtime-enforcer/internal/resolver"
	"github.com/kubewarden/runtime-enforcer/internal/violationbuf"
	pb "github.com/kubewarden/runtime-enforcer/proto/agent/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// agentObserver implements the AgentObserver gRPC server.
type agentObserver struct {
	pb.UnimplementedAgentObserverServer

	logger          *slog.Logger
	resolver        *resolver.Resolver
	violationBuffer *violationbuf.Buffer
}

func newAgentObserver(
	logger *slog.Logger,
	resolver *resolver.Resolver,
	violationBuffer *violationbuf.Buffer,
) *agentObserver {
	return &agentObserver{
		logger:          logger.With("component", "agent_observer"),
		resolver:        resolver,
		violationBuffer: violationBuffer,
	}
}

// ListPoliciesStatus list policies inside the resolver and returns their status.
func (s *agentObserver) ListPoliciesStatus(
	ctx context.Context,
	_ *pb.ListPoliciesStatusRequest,
) (*pb.ListPoliciesStatusResponse, error) {
	out := &pb.ListPoliciesStatusResponse{
		Policies: make(map[string]*pb.PolicyStatus),
	}

	statuses := s.resolver.GetPolicyStatuses()
	for policyName, ps := range statuses {
		out.Policies[policyName] = &pb.PolicyStatus{
			State:   ps.State,
			Mode:    ps.Mode,
			Message: ps.Message,
		}
	}

	s.logger.DebugContext(ctx, "listed tracing policies", "count", len(out.GetPolicies()))
	return out, nil
}

func podViewToProto(podView *resolver.PodView) *pb.PodView {
	view := &pb.PodView{
		Meta: &pb.PodMeta{
			Id:           podView.Meta.ID,
			Name:         podView.Meta.Name,
			Namespace:    podView.Meta.Namespace,
			WorkloadName: podView.Meta.WorkloadName,
			WorkloadType: podView.Meta.WorkloadType,
			Labels:       podView.Meta.Labels,
		},
		Containers: make(map[string]*pb.ContainerMeta, len(podView.Containers)),
	}
	for containerID, containerMeta := range podView.Containers {
		view.Containers[containerID] = &pb.ContainerMeta{
			Id:       containerID,
			Name:     containerMeta.Name,
			CgroupId: containerMeta.CgroupID,
		}
	}
	return view
}

// ListPodCache lists the current pod cache.
func (s *agentObserver) ListPodCache(
	ctx context.Context,
	_ *pb.ListPodCacheRequest,
) (*pb.ListPodCacheResponse, error) {
	out := &pb.ListPodCacheResponse{
		Pods: []*pb.PodView{},
	}

	snapshot := s.resolver.PodCacheSnapshot()
	for _, podView := range snapshot {
		out.Pods = append(out.Pods, podViewToProto(&podView))
	}

	s.logger.DebugContext(ctx, "listed pod cache", "count", len(out.GetPods()))
	return out, nil
}

// ScrapeViolations drains the agent's in-memory violation buffer and returns
// all accumulated records since the last scrape.
func (s *agentObserver) ScrapeViolations(
	ctx context.Context,
	_ *pb.ScrapeViolationsRequest,
) (*pb.ScrapeViolationsResponse, error) {
	records := s.violationBuffer.Drain()

	out := &pb.ScrapeViolationsResponse{
		Violations: make([]*pb.ViolationRecord, 0, len(records)),
	}

	for _, rec := range records {
		out.Violations = append(out.Violations, &pb.ViolationRecord{
			Timestamp:      timestamppb.New(rec.Timestamp),
			PodName:        rec.PodName,
			ContainerName:  rec.ContainerName,
			ExecutablePath: rec.ExePath,
			NodeName:       rec.NodeName,
			Action:         rec.Action,
			PolicyName:     rec.Namespace + "/" + rec.PolicyName,
			WorkloadName:   rec.WorkloadName,
			WorkloadKind:   rec.WorkloadKind,
		})
	}

	s.logger.DebugContext(ctx, "scraped violations", "count", len(out.GetViolations()))
	return out, nil
}
