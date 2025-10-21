package main

import (
	"flag"
	"os"

	"github.com/neuvector/runtime-enforcement/internal/eventhandler"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"

	securityv1alpha1 "github.com/neuvector/runtime-enforcement/api/v1alpha1"
	internalTetragon "github.com/neuvector/runtime-enforcement/internal/tetragon"

	"log/slog"
)

// DefaultEventChannelBufferSize defines the channel buffer size used to
// deliver Tetragon events to tetragon_event_controller.
const DefaultEventChannelBufferSize = 100

func main() {
	var err error
	var connector *internalTetragon.Connector

	opts := zap.Options{
		Development: true,
	}
	opts.BindFlags(flag.CommandLine)
	flag.Parse()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	})).With("component", "daemon")

	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))

	ctx := ctrl.SetupSignalHandler()

	scheme := runtime.NewScheme()
	err = securityv1alpha1.AddToScheme(scheme)
	if err != nil {
		logger.ErrorContext(ctx, "failed to initialize scheme", "error", err)
		os.Exit(1)
	}

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme: scheme,
	})
	if err != nil {
		logger.ErrorContext(ctx, "unable to start manager", "error", err)
		os.Exit(1)
	}

	tetragonEventReconciler := eventhandler.TetragonEventReconciler{
		Client:    mgr.GetClient(),
		Scheme:    mgr.GetScheme(),
		EventChan: make(chan event.TypedGenericEvent[eventhandler.ProcessLearningEvent], DefaultEventChannelBufferSize),
	}

	if err = tetragonEventReconciler.SetupWithManager(mgr); err != nil {
		logger.ErrorContext(ctx, "unable to create tetragon event reconciler", "error", err)
		os.Exit(1)
	}

	connector, err = internalTetragon.CreateConnector(logger, tetragonEventReconciler.EnqueueEvent)
	if err != nil {
		logger.ErrorContext(ctx, "failed to create tetragon connector", "error", err)
		os.Exit(1)
	}

	// StartEventLoop will receive events from Tetragon and send to event handler for process learning.
	if err = connector.Start(ctx); err != nil {
		logger.ErrorContext(ctx, "failed to start event loop", "error", err)
		os.Exit(1)
	}

	logger.InfoContext(ctx, "starting manager")
	if err = mgr.Start(ctx); err != nil {
		logger.ErrorContext(ctx, "failed to run manager", "error", err)
		os.Exit(1)
	}
}
