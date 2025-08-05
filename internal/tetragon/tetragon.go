package tetragon

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"time"

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
		// TODO: review if we should include host processes.

		// TODO: Tetragon only provides the labels when the Pod starts
		// but we're supposed to be able to use workload field instead.
		// "workload":"ubuntu-privileged", "workload_kind":"Pod"
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

func ConvertTetragonEvent(e *tetragon.GetEventsResponse) (*eventhandler.ProcessLearningEvent, error) {
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
		ContainerName:  pod.GetContainer().GetId(),
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

		// Learn the behavior
		processEvent, err = ConvertTetragonEvent(res)
		if err != nil {
			c.logger.DebugContext(ctx, "failed to handle event", "error", err)
			continue
		}

		c.enqueueFunc(ctx, *processEvent)
	}
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
