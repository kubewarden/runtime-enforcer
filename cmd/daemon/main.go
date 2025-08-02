package main

import (
	"context"
	"os"

	"github.com/neuvector/runtime-enforcement/internal/event"
	"github.com/neuvector/runtime-enforcement/internal/learner"

	"log/slog"

	"k8s.io/client-go/rest"

	internalTetragon "github.com/neuvector/runtime-enforcement/internal/tetragon"
)

func main() {
	// TODO: retry and default policies
	// TODO: parse flags

	var connector *internalTetragon.Connector
	var conf *rest.Config
	var err error

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	})).With("component", "daemon")

	// TODO: Only in-cluster config right now.
	ctx := context.Background()
	conf, err = rest.InClusterConfig()
	if err != nil {
		logger.ErrorContext(ctx, "failed to get in-cluster config", "error", err)
		os.Exit(1)
	}

	eventAggregator := event.CreateEventAggregator(logger)

	connector, err = internalTetragon.CreateConnector(logger)
	if err != nil {
		logger.ErrorContext(ctx, "failed to create tetragon connector", "error", err)
		os.Exit(1)
	}

	// Retrieve events from Tetragon.
	if err = connector.StartEventloop(ctx, eventAggregator, conf); err != nil {
		logger.ErrorContext(ctx, "failed to start event loop", "error", err)
		os.Exit(1)
	}

	logger.InfoContext(ctx, "security event loop has started")

	// Create learner, which will receive events from event aggregator and perform actions based on policy.
	// TODO: Use a channel?
	ruleLearner := learner.CreateLearner(logger, conf, eventAggregator)
	if err = ruleLearner.Start(ctx); err != nil {
		logger.ErrorContext(ctx, "failed to handle events", "error", err)
		os.Exit(1)
	}

	logger.InfoContext(ctx, "event learner has started")

	<-ctx.Done()
}
