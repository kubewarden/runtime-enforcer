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

type Config struct {
	enableTracing     bool
	enableOtelSidecar bool
	enableLearning    bool
}

func startTetragonEventController(ctx context.Context, logger *slog.Logger, enableLearning bool) error {
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

	// Initialize with a panic function, replaced when learning is enabled
	enqueueFunc := func(_ context.Context, _ eventhandler.ProcessLearningEvent) {
		panic("enqueue function should be never called when learning is disabled")
	}

	if enableLearning {
		tetragonEventReconciler := eventhandler.NewTetragonEventReconciler(mgr.GetClient(), mgr.GetScheme())
		if err = tetragonEventReconciler.SetupWithManager(mgr); err != nil {
			return fmt.Errorf("unable to create tetragon event reconciler: %w", err)
		}
		enqueueFunc = tetragonEventReconciler.EnqueueEvent
		logger.InfoContext(ctx, "learning mode is enabled")
	} else {
		logger.InfoContext(ctx, "learning mode is disabled")
	}

	connector, err = internalTetragon.CreateConnector(logger, enqueueFunc, enableLearning)
	if err != nil {
		return fmt.Errorf("failed to create tetragon connector: %w", err)
	}

	if err = mgr.Add(connector); err != nil {
		return fmt.Errorf("failed to add tetragon connector to manager: %w", err)
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
	flag.BoolVar(&config.enableLearning, "enable-learning", false, "Enable learning mode")

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
	if err = startTetragonEventController(ctx, logger, config.enableLearning); err != nil {
		logger.ErrorContext(ctx, "failed to start tetragon event controller", "error", err)
		os.Exit(1)
	}

	if traceShutdown != nil {
		if err = traceShutdown(ctx); err != nil {
			logger.ErrorContext(ctx, "failed to shutdown telemetry trace", "error", err)
		}
	}
}
