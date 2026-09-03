package main

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"time"

	"github.com/go-logr/logr"
	"github.com/kubewarden/runtime-enforcer/internal/debugger"
	"github.com/kubewarden/runtime-enforcer/internal/grpcexporter"
	"golang.org/x/sync/errgroup"
	ctrl "sigs.k8s.io/controller-runtime"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// +kubebuilder:rbac:groups="",resources=pods,verbs=get;list;watch

const (
	defaultInterval = 10 * time.Second
)

type conf struct {
	interval      time.Duration
	agentPoolConf grpcexporter.AgentClientPoolConfig
}

func loadConfig() (conf, error) {
	var config conf

	// DEBUGGER_GRPC_PORT
	portStr := os.Getenv("DEBUGGER_GRPC_PORT")
	if portStr == "" {
		config.agentPoolConf.Port = grpcexporter.DefaultAgentPort
	} else {
		port, err := strconv.Atoi(portStr)
		if err != nil {
			return conf{}, fmt.Errorf("invalid DEBUGGER_GRPC_PORT %q: %w", portStr, err)
		}
		config.agentPoolConf.Port = port
	}

	// DEBUGGER_INTERVAL
	intervalStr := os.Getenv("DEBUGGER_INTERVAL")
	if intervalStr == "" {
		config.interval = defaultInterval
	} else {
		interval, err := time.ParseDuration(intervalStr)
		if err != nil {
			return conf{}, fmt.Errorf("invalid DEBUGGER_INTERVAL %q: %w", intervalStr, err)
		}
		config.interval = interval
	}

	// DEBUGGER_AGENT_LABEL_SELECTOR
	labelSelector := os.Getenv("DEBUGGER_AGENT_LABEL_SELECTOR")
	if labelSelector == "" {
		config.agentPoolConf.LabelSelectorString = grpcexporter.DefaultAgentLabelSelectorString
	} else {
		config.agentPoolConf.LabelSelectorString = labelSelector
	}

	// DEBUGGER_CERT_DIR
	certDir := os.Getenv("DEBUGGER_CERT_DIR")
	if certDir == "" {
		config.agentPoolConf.CertDirPath = grpcexporter.DefaultCertDirPath
	} else {
		config.agentPoolConf.CertDirPath = certDir
	}

	return config, nil
}

func getPodCache() (cache.Cache, error) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	c, err := cache.New(ctrl.GetConfigOrDie(), cache.Options{
		Scheme: scheme,
		ByObject: map[client.Object]cache.ByObject{
			&corev1.Pod{}: {}, // Only pod informer
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create cache: %w", err)
	}
	return c, nil
}

func main() {
	// Set the logger
	slogHandler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo})
	slogger := slog.New(slogHandler).With("component", "debugger")
	slog.SetDefault(slogger)
	ctrl.SetLogger(logr.FromSlogHandler(slogger.Handler()))

	config, err := loadConfig()
	if err != nil {
		slogger.Error("Failed to load configuration", "error", err)
		os.Exit(1)
	}

	cache, err := getPodCache()
	if err != nil {
		slogger.Error("Failed to get pod cache", "error", err)
		os.Exit(1)
	}

	// Enable mTLS by default
	config.agentPoolConf.MTLSEnabled = true
	config.agentPoolConf.Logger = slog.New(slogHandler).With("component", "agent-pool")
	var pool *grpcexporter.AgentClientPool
	pool, err = grpcexporter.NewAgentClientPool(config.agentPoolConf)
	if err != nil {
		slogger.Error("Failed to create agent client pool", "error", err)
		os.Exit(1)
	}

	// we return in case of signals
	g, ctx := errgroup.WithContext(ctrl.SetupSignalHandler())

	// Start the cache
	g.Go(func() error {
		return cache.Start(ctx)
	})

	// Wait for the cache to be ready and then start the validation.
	g.Go(func() error {
		if !cache.WaitForCacheSync(ctx) {
			return errors.New("timeout cache synchronization")
		}

		for {
			select {
			case <-ctx.Done():
				// We terminate.
				return nil
			case <-time.After(config.interval):
				if err = debugger.ValidatePodCacheIntegrity(ctx, slogger, cache, pool); err != nil {
					slogger.Error("Failed to validate pod cache integrity", "error", err)
				}
			}
		}
	})

	if err = g.Wait(); err != nil {
		slogger.Error("Debugger stopped with error", "error", err)
		os.Exit(1)
	}
}
