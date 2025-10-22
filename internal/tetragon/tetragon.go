package tetragon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/neuvector/runtime-enforcement/internal/eventhandler"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
)

const (
	GRPCWaitForReadyTimeout = 30 * time.Second
	maxGRPCRecvSize         = 128 * 1024 * 1024 // 128mb
)

type Connector struct {
	logger      *slog.Logger
	client      tetragon.FineGuidanceSensorsClient
	tracer      trace.Tracer
	enqueueFunc func(context.Context, eventhandler.ProcessLearningEvent)
}

func CreateConnector(
	logger *slog.Logger,
	enqueueFunc func(context.Context, eventhandler.ProcessLearningEvent),
) (*Connector, error) {
	conn, err := grpc.NewClient("unix:///var/run/tetragon/tetragon.sock",
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to Tetragon gRPC server: %w", err)
	}

	tetragonClient := tetragon.NewFineGuidanceSensorsClient(conn)

	return &Connector{
		logger:      logger.With("component", "tetragon_connector"),
		client:      tetragonClient,
		enqueueFunc: enqueueFunc,
		tracer:      otel.Tracer("runtime-enforcement-enforcer"),
	}, nil
}

// FillInitialProcesses gets the existing process list from Tetragon and generate process events.
func (c *Connector) FillInitialProcesses(ctx context.Context) error {
	timeout, cancel := context.WithTimeout(ctx, GRPCWaitForReadyTimeout)
	defer cancel()

	resp, err := c.client.GetDebug(timeout, &tetragon.GetDebugRequest{
		Flag: tetragon.ConfigFlag_CONFIG_FLAG_DUMP_PROCESS_CACHE,
		Arg: &tetragon.GetDebugRequest_Dump{
			Dump: &tetragon.DumpProcessCacheReqArgs{
				SkipZeroRefcnt:            true,
				ExcludeExecveMapProcesses: false,
			},
		},
	}, grpc.WaitForReady(true), grpc.MaxCallRecvMsgSize(maxGRPCRecvSize))
	if err != nil {
		return fmt.Errorf("failed to get initial processes: %w", err)
	}

	procs := resp.GetProcesses()
	if procs == nil {
		return errors.New("no process list is available")
	}

	c.logger.InfoContext(ctx, "Receiving process list", "num", len(procs.GetProcesses()))

	for _, v := range procs.GetProcesses() {
		eventPod := v.GetProcess().GetPod()
		if eventPod != nil {
			c.enqueueFunc(ctx, eventhandler.ProcessLearningEvent{
				Namespace:      eventPod.GetNamespace(),
				ContainerName:  eventPod.GetContainer().GetName(),
				Workload:       eventPod.GetWorkload(),
				WorkloadKind:   eventPod.GetWorkloadKind(),
				ExecutablePath: v.GetProcess().GetBinary(),
			})
		}
	}
	return nil
}

func ConvertTetragonProcEvent(e *tetragon.GetEventsResponse) (*eventhandler.ProcessLearningEvent, error) {
	exec := e.GetProcessExec()

	if exec == nil {
		return nil, errors.New("not supported event")
	}

	proc := exec.GetProcess()
	if proc == nil {
		return nil, errors.New("not proc is associated with this event")
	}

	pod := proc.GetPod()
	if pod == nil {
		return nil, errors.New("ignore events that don't come with pod info")
	}

	processEvent := eventhandler.ProcessLearningEvent{
		Namespace:      pod.GetNamespace(),
		ContainerName:  pod.GetContainer().GetName(),
		Workload:       pod.GetWorkload(),
		WorkloadKind:   pod.GetWorkloadKind(),
		ExecutablePath: proc.GetBinary(),
	}

	return &processEvent, nil
}

// Read Tetragon events and feed into event aggregator.
func (c *Connector) eventLoop(ctx context.Context) error {
	var res *tetragon.GetEventsResponse
	var processEvent *eventhandler.ProcessLearningEvent
	var err error

	// Getting stream first.
	timeout, cancel := context.WithTimeout(ctx, GRPCWaitForReadyTimeout)
	defer cancel()

	req := tetragon.GetEventsRequest{}
	stream, err := c.client.GetEvents(timeout, &req, grpc.WaitForReady(true))

	if err != nil {
		return fmt.Errorf("failed to get events: %w", err)
	}

	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("tetragon event loop has completed: %w", ctx.Err())
		default:
		}

		res, err = stream.Recv()
		if err != nil {
			if !errors.Is(err, context.Canceled) && status.Code(err) != codes.Canceled && !errors.Is(err, io.EOF) {
				return fmt.Errorf("failed to receive events: %w", err)
			}
			return nil
		}

		// Ignore all unknown events
		switch res.GetEvent().(type) {
		case *tetragon.GetEventsResponse_ProcessExec:
			// Learn the behavior
			processEvent, err = ConvertTetragonProcEvent(res)
			if err != nil {
				c.logger.DebugContext(ctx, "failed to handle event", "error", err)
				continue
			}

			c.enqueueFunc(ctx, *processEvent)
		case *tetragon.GetEventsResponse_ProcessKprobe:
			// Emit OpenTelemetry traces
			c.handleKProbeEvent(ctx, res.GetProcessKprobe())
		}
	}
}

func (c *Connector) emitEnforcementEvent(
	ctx context.Context,
	policyName string,
	proc *tetragon.Process,
	exepath string,
	action Action,
) {
	now := time.Now()

	pod := proc.GetPod()

	var span trace.Span
	_, span = c.tracer.Start(ctx, string(action))
	span.SetAttributes(
		attribute.String("evt.time", now.Format(time.RFC3339)),
		attribute.Int64("evt.rawtime", now.UnixNano()),
		attribute.String("policy.name", policyName),
		attribute.String("k8s.ns.name", pod.GetNamespace()),
		attribute.String("k8s.workload.name", pod.GetWorkload()),
		attribute.String("k8s.workload.kind", pod.GetWorkloadKind()),
		attribute.String("k8s.pod.name", pod.GetName()),
		attribute.String("container.full_id", pod.GetContainer().GetId()),
		attribute.String("container.name", pod.GetContainer().GetName()),
		attribute.Int64("proc.pid", int64(proc.GetPid().GetValue())),
		attribute.String("proc.pexepath", proc.GetBinary()),
		attribute.String("proc.exepath", exepath),
		attribute.String("action", string(action)),
	)
	span.End()
}

func (c *Connector) handleKProbeEvent(ctx context.Context, evt *tetragon.ProcessKprobe) {
	args := evt.GetArgs()

	// TODO: make sure that the event is from the rule we created.
	if len(args) == 0 {
		c.logger.ErrorContext(ctx, "invalid kprobe events")
		return
	}

	linuxBprmArg := args[0].GetLinuxBinprmArg()

	if linuxBprmArg == nil {
		c.logger.ErrorContext(ctx, "no linux bprm arg is available")
		return
	}

	eb, err := json.Marshal(evt)
	if err != nil {
		c.logger.ErrorContext(ctx, "invalid kprobe events", "error", err)
		return
	}

	c.logger.DebugContext(ctx, "Getting kprobe event", "event", string(eb))

	var action Action
	action, err = GetAction(evt.GetAction().String())
	if err != nil {
		c.logger.ErrorContext(ctx, "unknown tetragon action", "error", err)
		return
	}

	c.emitEnforcementEvent(
		ctx,
		evt.GetPolicyName(),
		evt.GetProcess(),
		linuxBprmArg.GetPath(),
		action,
	)
}

func (c *Connector) Start(ctx context.Context) error {
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}
			if err := c.eventLoop(ctx); err != nil {
				c.logger.WarnContext(ctx, "failed to get events", "error", err)
			}
		}
	}()

	// TODO: we have to wait until a message from go routine is received, so we won't miss any events in between.
	if err := c.FillInitialProcesses(ctx); err != nil {
		return fmt.Errorf("failed to get all running processes: %w", err)
	}

	return nil
}
