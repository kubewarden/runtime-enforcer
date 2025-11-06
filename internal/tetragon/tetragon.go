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

	retry "github.com/avast/retry-go/v4"
	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/neuvector/runtime-enforcement/internal/eventhandler"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	GRPCWaitForReadyTimeout = 30 * time.Second
	maxGRPCRecvSize         = 128 * 1024 * 1024 // 128mb
	maxDelay                = 2 * time.Minute
	WorkloadKindPod         = "Pod"
)

type Connector struct {
	logger                       *slog.Logger
	tracer                       trace.Tracer
	enqueueFunc                  func(context.Context, eventhandler.ProcessLearningEvent)
	tetragonEvents               []tetragon.EventType
	initialProcessStatePopulated bool
}

// ErrPodInfoUnavailable signals that the event doesn't carry pod info
// (e.g., process is on the node). Callers can treat it as a non-fatal skip.
var ErrPodInfoUnavailable = errors.New("pod info unavailable on event")

// ErrPodWorkloadKindNotSupported signals that the pod workload kind is not supported
// Callers can treat it as a non-fatal skip.
var ErrPodWorkloadKindNotSupported = errors.New("pod workload kind is not supported")

func CreateConnector(
	logger *slog.Logger,
	enqueueFunc func(context.Context, eventhandler.ProcessLearningEvent),
	enableLearning bool,
) (*Connector, error) {
	conn := &Connector{
		logger:      logger.With("component", "tetragon_connector"),
		enqueueFunc: enqueueFunc,
		tracer:      otel.Tracer("runtime-enforcement-enforcer"),
		// by default we only listen for process kprobe events
		tetragonEvents: []tetragon.EventType{tetragon.EventType_PROCESS_KPROBE},
	}

	if enableLearning {
		// when learning is enabled we also listen for exec events
		conn.tetragonEvents = append(
			conn.tetragonEvents,
			tetragon.EventType_PROCESS_EXEC,
		)
	}
	return conn, nil
}

// FillInitialProcesses gets the existing process list from Tetragon and generate process events.
func (c *Connector) FillInitialProcesses(ctx context.Context) error {
	client, err := NewTetragonClient()
	if err != nil {
		return fmt.Errorf("failed create gRPC client: %w", err)
	}
	defer client.Close()

	req := &tetragon.GetDebugRequest{
		Flag: tetragon.ConfigFlag_CONFIG_FLAG_DUMP_PROCESS_CACHE,
		Arg: &tetragon.GetDebugRequest_Dump{
			Dump: &tetragon.DumpProcessCacheReqArgs{
				SkipZeroRefcnt:            true,
				ExcludeExecveMapProcesses: false,
			},
		},
	}

	timeout, timeoutCancel := context.WithTimeout(ctx, oneShotRequestTimeout)
	defer timeoutCancel()
	resp, err := client.Client.GetDebug(
		timeout,
		req,
		grpc.WaitForReady(true),
		grpc.MaxCallRecvMsgSize(maxGRPCRecvSize),
	)

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
		if eventPod == nil {
			continue
		}

		if eventPod.GetWorkloadKind() == WorkloadKindPod {
			continue
		}

		c.enqueueFunc(ctx, eventhandler.ProcessLearningEvent{
			Namespace:      eventPod.GetNamespace(),
			ContainerName:  eventPod.GetContainer().GetName(),
			Workload:       eventPod.GetWorkload(),
			WorkloadKind:   eventPod.GetWorkloadKind(),
			ExecutablePath: v.GetProcess().GetBinary(),
		})
	}
	return nil
}

func ConvertTetragonProcEvent(e *tetragon.GetEventsResponse) (*eventhandler.ProcessLearningEvent, error) {
	exec := e.GetProcessExec()

	if exec == nil {
		return nil, errors.New("received not supported event")
	}

	proc := exec.GetProcess()
	if proc == nil {
		return nil, errors.New("no proc is associated with this event")
	}

	pod := proc.GetPod()
	if pod == nil {
		// not an error: event refers to a non-pod process (node-level). Signal with sentinel.
		return nil, ErrPodInfoUnavailable
	}

	// For now we don't support learning for pods with workload kind "Pod"
	if pod.GetWorkloadKind() == WorkloadKindPod {
		return nil, ErrPodWorkloadKindNotSupported
	}

	return &eventhandler.ProcessLearningEvent{
		Namespace:      pod.GetNamespace(),
		ContainerName:  pod.GetContainer().GetName(),
		Workload:       pod.GetWorkload(),
		WorkloadKind:   pod.GetWorkloadKind(),
		ExecutablePath: proc.GetBinary(),
	}, nil
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

func (c *Connector) getEvents(ctx context.Context, client tetragon.FineGuidanceSensorsClient) error {
	// Every time we start a new connection to Tetragon we should get the initial process state
	// to decrease the risk of missing events. We do the initial process lookup after we receive
	// the first exec event to avoid missing events between the initial process dump and the start of
	// the event stream.
	c.initialProcessStatePopulated = false

	// We want:
	// - exec events
	// - violations events (kprobes)
	request := &tetragon.GetEventsRequest{
		AllowList: []*tetragon.Filter{
			{
				EventSet: c.tetragonEvents,
			},
		},
	}
	stream, err := client.GetEvents(ctx, request)
	if err != nil {
		return fmt.Errorf("failed to get events: %w", err)
	}

	for {
		var res *tetragon.GetEventsResponse
		res, err = stream.Recv()
		if err != nil {
			return err
		}

		if err = c.dispatchEvent(ctx, res); err != nil &&
			!errors.Is(err, ErrPodInfoUnavailable) &&
			!errors.Is(err, ErrPodWorkloadKindNotSupported) {
			c.logger.ErrorContext(ctx, "fail to dispatch event", "evt", res, "error", err)
		}
	}
}

// dispatchEvent routes a received Tetragon event to the appropriate handler.
func (c *Connector) dispatchEvent(ctx context.Context, recvRes *tetragon.GetEventsResponse) error {
	switch recvRes.GetEvent().(type) {
	case *tetragon.GetEventsResponse_ProcessExec:
		procEvt, err := ConvertTetragonProcEvent(recvRes)
		if err != nil {
			return err
		}
		c.enqueueFunc(ctx, *procEvt)
		// Only once for each connection we want to get the initial process state
		// when we receive the first exec event
		if !c.initialProcessStatePopulated {
			if err = c.FillInitialProcesses(ctx); err != nil {
				return err
			}
			c.logger.InfoContext(ctx, "Correctly received initial process list")
			c.initialProcessStatePopulated = true
		}
	case *tetragon.GetEventsResponse_ProcessKprobe:
		c.handleKProbeEvent(ctx, recvRes.GetProcessKprobe())
	default:
		return errors.New("received unsupported event type")
	}
	return nil
}

func (c *Connector) GetEventsFromTetragon(ctx context.Context) error {
	// isRetryable is called only in case of err != nil
	isRetryable := func(err error) bool {
		// Stop retrying if context has been canceled.
		if status.Code(err) == codes.Canceled ||
			errors.Is(err, context.Canceled) {
			return false
		}
		c.logger.WarnContext(ctx, "error receiving events from Tetragon, retrying...", "error", err)
		return true
	}

	tryConnectAndStream := func() error {
		c.logger.InfoContext(ctx, "connecting to Tetragon to receive events")
		client, err := NewTetragonClient()
		if err != nil {
			c.logger.WarnContext(ctx, "failed create gRPC client", "error", err)
			return err
		}
		defer client.Close()

		// Handle stream until it ends or errors out.
		err = c.getEvents(ctx, client.Client)
		if errors.Is(err, io.EOF) {
			c.logger.InfoContext(ctx, "Tetragon event stream closed by server")
			// Returning nil immediately stops the backoff retries.
			return nil
		}
		return err
	}

	for {
		err := retry.Do(
			tryConnectAndStream,
			retry.Attempts(0),
			retry.Delay(time.Second),
			retry.DelayType(retry.BackOffDelay),
			retry.MaxDelay(maxDelay),
			retry.RetryIf(isRetryable),
		)
		if err != nil {
			// the only case in which we should enter here is when the context is canceled
			c.logger.InfoContext(ctx, "Tetragon event stream closed", "msg", err)
			// We return nil since this is the expected behavior when the context is canceled and the controller runtime shouldn't receive an error.
			return nil
		}
	}
}

// Start implements the runnable interface for the controller-runtime manager.
func (c *Connector) Start(ctx context.Context) error {
	return c.GetEventsFromTetragon(ctx)
}
