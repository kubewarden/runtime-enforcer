package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/neuvector/runtime-enforcement/internal/eventhandler"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"

	securityv1alpha1 "github.com/neuvector/runtime-enforcement/api/v1alpha1"
	internalTetragon "github.com/neuvector/runtime-enforcement/internal/tetragon"
	"github.com/neuvector/runtime-enforcement/internal/traces"

	"log/slog"
)

// DefaultEventChannelBufferSize defines the channel buffer size used to
// deliver Tetragon events to tetragon_event_controller.
const DefaultEventChannelBufferSize = 100

type Config struct {
	enableTracing     bool
	enableOtelSidecar bool
}

func startTetragonEventController(ctx context.Context, logger *slog.Logger) error {
	var err error
	var connector *internalTetragon.Connector

	scheme := runtime.NewScheme()
	err = securityv1alpha1.AddToScheme(scheme)
	if err != nil {
		return fmt.Errorf("failed to initialize scheme: %w", err)
	}

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme: scheme,
	})
	if err != nil {
		return fmt.Errorf("unable to start manager: %w", err)
	}

	tetragonEventReconciler := eventhandler.NewTetragonEventReconciler(mgr.GetClient(), mgr.GetScheme())

	if err = tetragonEventReconciler.SetupWithManager(mgr); err != nil {
		return fmt.Errorf("unable to create tetragon event reconciler: %w", err)
	}

	connector, err = internalTetragon.CreateConnector(logger, tetragonEventReconciler.EnqueueEvent)
	if err != nil {
		return fmt.Errorf("failed to create tetragon connector: %w", err)
	}

	// StartEventLoop will receive events from Tetragon and send to event handler for process learning.
	if err = connector.Start(ctx); err != nil {
		return fmt.Errorf("failed to start tetragon connector: %w", err)
	}

	logger.InfoContext(ctx, "starting manager")
	if err = mgr.Start(ctx); err != nil {
		logger.ErrorContext(ctx, "failed to start manager", "error", err)
	}

	return nil
}

func main() {
	var err error
	var config Config

	var traceShutdown func(context.Context) error

	ctx := ctrl.SetupSignalHandler()

	opts := zap.Options{
		Development: true,
	}
	opts.BindFlags(flag.CommandLine)

	flag.BoolVar(&config.enableTracing, "enable-tracing", false, "Enable tracing collection")
	flag.BoolVar(&config.enableOtelSidecar, "enable-otel-sidecar", false, "Enable OpenTelemetry sidecar")

	flag.Parse()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	})).With("component", "daemon")

	if config.enableTracing {
		// Start otel traces
		traceShutdown, err = traces.Init()
		if err != nil {
			logger.ErrorContext(ctx, "failed to initiate open telemetry trace", "error", err)
			os.Exit(1)
		}
	}

	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))

	// This function blocks if everything is alright.
	if err = startTetragonEventController(ctx, logger); err != nil {
		logger.ErrorContext(ctx, "failed to start tetragon event controller", "error", err)
		os.Exit(1)
	}

	if traceShutdown != nil {
		if err = traceShutdown(ctx); err != nil {
			logger.ErrorContext(ctx, "failed to shutdown telemetry trace", "error", err)
		}
	}
}
