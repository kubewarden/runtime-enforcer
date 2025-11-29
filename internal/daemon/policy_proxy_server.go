package daemon

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/neuvector/runtime-enforcer/internal/defaults"
	internalTetragon "github.com/neuvector/runtime-enforcer/internal/tetragon"
	pb "github.com/neuvector/runtime-enforcer/proto/policyproxy/v1"
	"google.golang.org/grpc"
)

// policyProxyServer implements the PolicyProxyService gRPC server.
type policyProxyServer struct {
	pb.UnimplementedPolicyProxyServiceServer

	logger *slog.Logger
}

func newPolicyProxyServer(logger *slog.Logger) *policyProxyServer {
	return &policyProxyServer{logger: logger.With("component", "policy_proxy")}
}

func convertPolicyState(state tetragon.TracingPolicyState) pb.TracingPolicyState {
	switch state {
	case tetragon.TracingPolicyState_TP_STATE_UNKNOWN:
		return pb.TracingPolicyState_TP_STATE_UNKNOWN
	case tetragon.TracingPolicyState_TP_STATE_ENABLED:
		return pb.TracingPolicyState_TP_STATE_ENABLED
	case tetragon.TracingPolicyState_TP_STATE_DISABLED:
		return pb.TracingPolicyState_TP_STATE_DISABLED
	case tetragon.TracingPolicyState_TP_STATE_LOAD_ERROR:
		return pb.TracingPolicyState_TP_STATE_LOAD_ERROR
	case tetragon.TracingPolicyState_TP_STATE_ERROR:
		return pb.TracingPolicyState_TP_STATE_ERROR
	case tetragon.TracingPolicyState_TP_STATE_LOADING:
		return pb.TracingPolicyState_TP_STATE_LOADING
	case tetragon.TracingPolicyState_TP_STATE_UNLOADING:
		return pb.TracingPolicyState_TP_STATE_UNLOADING
	default:
		// if we panic it means we are desynchronised with tetragon api
		panic(fmt.Sprintf("unhandled tracing policy state: %v", state))
	}
}

// ListPoliciesStatus calls Tetragon ListTracingPolicies and maps the result.
func (s *policyProxyServer) ListPoliciesStatus(
	ctx context.Context,
	_ *pb.ListPoliciesStatusRequest,
) (*pb.ListPoliciesStatusResponse, error) {
	client, err := internalTetragon.NewTetragonClient()
	if err != nil {
		return nil, fmt.Errorf("failed to create tetragon client: %w", err)
	}
	defer client.Close()

	timeoutCtx, timeoutCancel := context.WithTimeout(ctx, internalTetragon.OneShotRequestTimeout)
	defer timeoutCancel()

	resp, err := client.Client.ListTracingPolicies(
		timeoutCtx,
		&tetragon.ListTracingPoliciesRequest{},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to get list of tracing policies: %w", err)
	}

	out := &pb.ListPoliciesStatusResponse{
		Policies: make(map[string]*pb.PolicyStatus),
	}

	for _, p := range resp.GetPolicies() {
		key := p.GetName() + "/" + p.GetNamespace()
		if _, exists := out.GetPolicies()[key]; exists {
			s.logger.ErrorContext(ctx, "duplicate tracing policy name/namespace detected", "key", key)
			return nil, fmt.Errorf("duplicate tracing policy name/namespace detected '%s': %w", key, err)
		}
		out.Policies[key] = &pb.PolicyStatus{
			State: convertPolicyState(p.GetState()),
		}
	}

	s.logger.DebugContext(ctx, "listed tracing policies", "count", len(out.GetPolicies()))
	return out, nil
}

type Server struct {
	logger *slog.Logger
	addr   string
}

func NewServer(logger *slog.Logger) (*Server, error) {
	addr := os.Getenv(defaults.PolicyProxyGRPCAddressEnvKey)
	if addr == "" {
		return nil, fmt.Errorf("environment variable '%s' is not set", defaults.PolicyProxyGRPCAddressEnvKey)
	}
	return &Server{logger: logger, addr: addr}, nil
}

func (g *Server) Start(ctx context.Context) error {
	lc := net.ListenConfig{}
	listener, err := lc.Listen(ctx, "tcp", g.addr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", g.addr, err)
	}
	grpcServer := grpc.NewServer()
	pb.RegisterPolicyProxyServiceServer(grpcServer, newPolicyProxyServer(g.logger))
	return grpcServer.Serve(listener)
}
