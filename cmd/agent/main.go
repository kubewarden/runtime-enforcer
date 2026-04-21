package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/avast/retry-go/v4"
	"github.com/go-logr/logr"

	securityv1alpha1 "github.com/rancher-sandbox/runtime-enforcer/api/v1alpha1"
	"github.com/rancher-sandbox/runtime-enforcer/internal/bpf"
	"github.com/rancher-sandbox/runtime-enforcer/internal/eventhandler"
	"github.com/rancher-sandbox/runtime-enforcer/internal/events"
	"github.com/rancher-sandbox/runtime-enforcer/internal/eventscraper"
	"github.com/rancher-sandbox/runtime-enforcer/internal/grpcexporter"
	"github.com/rancher-sandbox/runtime-enforcer/internal/nri"
	"github.com/rancher-sandbox/runtime-enforcer/internal/ocihook"
	"github.com/rancher-sandbox/runtime-enforcer/internal/resolver"
	"github.com/rancher-sandbox/runtime-enforcer/internal/types/loglevel"
	"github.com/rancher-sandbox/runtime-enforcer/internal/workloadpolicyhandler"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"

	"github.com/rancher-sandbox/runtime-enforcer/internal/violationbuf"
	otellog "go.opentelemetry.io/otel/log"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"
)

type Config struct {
	learningNamespaceSelector string
	nriSocketPath             string
	nriPluginIdx              string
	ociHookSocket             string
	ociHookBin                string
	probeAddr                 string
	grpcConf                  grpcexporter.Config
	logLevel                  string
	otlpEndpoint              string
	otlpProtocol              string
	otlpCACert                string
	otlpClientCert            string
	otlpClientKey             string
	nodeName                  string
	violationLogger           otellog.Logger
}

func (c Config) learningEnabled() bool {
	return strings.TrimSpace(c.learningNamespaceSelector) != ""
}

func newControllerManager(config Config) (manager.Manager, error) {
	scheme := runtime.NewScheme()
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(securityv1alpha1.AddToScheme(scheme))
	controllerOptions := ctrl.Options{
		Scheme:                 scheme,
		HealthProbeBindAddress: config.probeAddr,
	}
	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), controllerOptions)
	if err != nil {
		return nil, fmt.Errorf("unable to start manager: %w", err)
	}
	return mgr, nil
}

func setupGRPCExporter(
	ctrlMgr manager.Manager,
	logger *slog.Logger,
	conf *grpcexporter.Config,
	r *resolver.Resolver,
	violationBuffer *violationbuf.Buffer,
) error {
	exporter, err := grpcexporter.New(logger, conf, r, violationBuffer)
	if err != nil {
		return fmt.Errorf("failed to create gRPC exporter: %w", err)
	}
	if err = ctrlMgr.Add(exporter); err != nil {
		return fmt.Errorf("failed to add gRPC exporter to controller manager: %w", err)
	}
	return nil
}

func setupWorkloadPolicyHandler(
	ctrlMgr manager.Manager,
	logger *slog.Logger,
	resolver *resolver.Resolver,
) error {
	wpHandler := workloadpolicyhandler.NewWorkloadPolicyHandler(ctrlMgr.GetClient(), logger, resolver)
	err := wpHandler.SetupWithManager(ctrlMgr)
	if err != nil {
		return fmt.Errorf("unable to set up WorkloadPolicy handler: %w", err)
	}
	// controller-runtime doesn't support a separate startup probe, so we use the readiness probe instead.
	// See https://github.com/kubernetes-sigs/controller-runtime/issues/2644 for more details.
	if err = ctrlMgr.AddReadyzCheck("policy readyz", func(req *http.Request) error {
		if syncErr := wpHandler.HasSynced(req.Context()); syncErr != nil {
			logger.ErrorContext(req.Context(), "WorkloadPolicy handler is not synced", "error", syncErr)
			return fmt.Errorf("WorkloadPolicy handler is not synced: %w", syncErr)
		}
		return nil
	}); err != nil {
		return fmt.Errorf("failed to add policy readiness probe: %w", err)
	}

	return nil
}

func waitForMutatingAdmissionWebhook(ctx context.Context) error {
	const (
		connectionTimeout = 3 * time.Second
		attempts          = 5
	)

	mutatingWebhookEP := os.Getenv("RUNTIME_ENFORCER_WEBHOOK_ENDPOINT")
	if mutatingWebhookEP == "" {
		return errors.New("RUNTIME_ENFORCER_WEBHOOK_ENDPOINT environment variable is not set")
	}

	tryConnect := func() error {
		d := net.Dialer{
			Timeout: connectionTimeout,
		}
		conn, err := d.DialContext(
			ctx,
			"tcp",
			net.JoinHostPort(mutatingWebhookEP, "443"),
		)
		if err != nil {
			return err
		}
		_ = conn.Close()

		return nil
	}

	return retry.Do(
		tryConnect,
		retry.Context(ctx),
		retry.Attempts(attempts),
		retry.Delay(time.Second),
		retry.DelayType(retry.BackOffDelay),
		retry.OnRetry(func(n uint, err error) {
			// n = 0 for the first retry
			logger := log.FromContext(ctx)
			logger.V(loglevel.VerbosityDebug).
				Info("error during mutating webhook socket connection, retrying...",
					"attempt", n+1,
					"error", err,
				)
		}),
	)
}

func setupLearningReconciler(
	ctx context.Context,
	logger *slog.Logger,
	config Config,
	ctrlMgr manager.Manager,
) (func(eventscraper.KubeProcessInfo), error) {
	if !config.learningEnabled() {
		logger.InfoContext(ctx, "learning mode is disabled")
		return func(_ eventscraper.KubeProcessInfo) {
			panic("enqueue function should be never called when learning is disabled")
		}, nil
	}

	var nsSelector labels.Selector
	selector, err := parseLearningNamespaceSelector(config.learningNamespaceSelector)
	if err != nil {
		return nil, fmt.Errorf("invalid learning-namespace-selector %q: %w", config.learningNamespaceSelector, err)
	}
	nsSelector = selector

	// Wait until mutating admission webhook is ready.
	if err = waitForMutatingAdmissionWebhook(ctx); err != nil {
		return nil, err
	}

	learningReconciler := eventhandler.NewLearningReconciler(ctrlMgr.GetClient(), nsSelector)
	if err = learningReconciler.SetupWithManager(ctrlMgr); err != nil {
		return nil, fmt.Errorf("unable to create learning reconciler: %w", err)
	}
	logger.InfoContext(ctx, "learning mode is enabled", "namespaceSelector", config.learningNamespaceSelector)
	return learningReconciler.EnqueueEvent, nil
}

func startAgent(ctx context.Context, logger *slog.Logger, config Config) error {
	var err error

	//////////////////////
	// Create controller manager
	//////////////////////
	ctrlMgr, err := newControllerManager(config)
	if err != nil {
		return fmt.Errorf("cannot create manager: %w", err)
	}

	//////////////////////
	// Create BPF manager
	//////////////////////
	bpfManager, err := bpf.NewManager(logger, config.learningEnabled())
	if err != nil {
		return fmt.Errorf("cannot create BPF manager: %w", err)
	}
	if err = ctrlMgr.Add(bpfManager); err != nil {
		return fmt.Errorf("failed to add BPF manager to controller manager: %w", err)
	}

	//////////////////////
	// Create Learning Reconciler if learning is enabled
	//////////////////////
	enqueueFunc, err := setupLearningReconciler(ctx, logger, config, ctrlMgr)
	if err != nil {
		return err
	}

	//////////////////////
	// Create the resolver
	//////////////////////
	resolver, err := resolver.NewResolver(
		logger,
		bpfManager.GetCgroupTrackerUpdateFunc(),
		bpfManager.GetCgroupPolicyUpdateFunc(),
		bpfManager.GetPolicyUpdateBinariesFunc(),
		bpfManager.GetPolicyModeUpdateFunc(),
	)
	if err != nil {
		return fmt.Errorf("failed to create resolver: %w", err)
	}

	if err = setupWorkloadPolicyHandler(ctrlMgr, logger, resolver); err != nil {
		return err
	}

	var nriHandler *nri.Handler
	nriHandler, err = nri.NewNRIHandler(
		config.nriSocketPath,
		config.nriPluginIdx,
		config.ociHookSocket,
		config.ociHookBin,
		logger,
		resolver,
	)

	if err != nil {
		return fmt.Errorf("failed to create NRI handler: %w", err)
	}
	if err = ctrlMgr.Add(nriHandler); err != nil {
		return fmt.Errorf("failed to add NRI handler to controller manager: %w", err)
	}

	// controller-runtime doesn't support a separate startup probe, so we use the readiness probe instead.
	// See https://github.com/kubernetes-sigs/controller-runtime/issues/2644 for more details.
	if err = ctrlMgr.AddReadyzCheck("resolver readyz", resolver.Ping); err != nil {
		return fmt.Errorf("failed to add resolver's readiness probe: %w", err)
	}

	//////////////////////
	// Create the violation buffer
	//////////////////////
	violationBuffer := violationbuf.NewBuffer()

	//////////////////////
	// Create the scraper
	//////////////////////
	var scraperOpts []eventscraper.Option
	if config.violationLogger != nil {
		scraperOpts = append(scraperOpts, eventscraper.WithViolationLogger(config.violationLogger, config.nodeName))
	}
	scraperOpts = append(scraperOpts, eventscraper.WithViolationBuffer(violationBuffer, config.nodeName))
	evtScraper := eventscraper.NewEventScraper(
		bpfManager.GetLearningChannel(),
		bpfManager.GetMonitoringChannel(),
		logger,
		resolver,
		enqueueFunc,
		scraperOpts...,
	)
	if err = ctrlMgr.Add(evtScraper); err != nil {
		return fmt.Errorf("failed to add event scraper to controller manager: %w", err)
	}

	//////////////////////
	// Add OCI hook handler
	//////////////////////
	ociHook := ocihook.NewHandler(
		config.ociHookSocket,
		bpfManager.GetCgroupTrackerUpdateFunc(),
	)
	if err = ctrlMgr.Add(ociHook); err != nil {
		return fmt.Errorf("failed to add OCI hook handler to controller manager: %w", err)
	}

	//////////////////////
	// Add GRPC exporter
	//////////////////////
	if err = setupGRPCExporter(ctrlMgr, logger, &config.grpcConf, resolver, violationBuffer); err != nil {
		return err
	}

	logger.InfoContext(ctx, "starting manager")
	if err = ctrlMgr.Start(ctx); err != nil {
		return fmt.Errorf("failed to start manager: %w", err)
	}

	return nil
}

// parseLearningNamespaceSelector parses the learning namespace selector from a JSON object (e.g. {"matchLabels":{"env":"prod"}}).
func parseLearningNamespaceSelector(s string) (labels.Selector, error) {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, "{") {
		return nil, fmt.Errorf("invalid JSON label selector %q: must be a JSON object", s)
	}

	var ls metav1.LabelSelector
	if err := json.Unmarshal([]byte(s), &ls); err != nil {
		return nil, fmt.Errorf("invalid JSON label selector %q: %w", s, err)
	}
	selector, err := metav1.LabelSelectorAsSelector(&ls)
	if err != nil {
		return nil, err
	}

	if selector.Empty() {
		return nil, fmt.Errorf("invalid JSON label selector %q: must not be empty if learning is enabled", s)
	}
	return selector, nil
}

func parseFlags() Config {
	var config Config
	// If we receive something different from "", it should be a valid json
	flag.StringVar(
		&config.learningNamespaceSelector,
		"learning-namespace-selector",
		"",
		"Namespace selector for learning. Accepts a JSON LabelSelector",
	)
	flag.StringVar(&config.nriSocketPath, "nri-socket-path", "/var/run/nri/nri.sock", "NRI socket path")
	flag.StringVar(&config.nriPluginIdx, "nri-plugin-index", "00", "NRI plugin index")
	flag.StringVar(&config.ociHookSocket, "oci-hook-socket", "/opt/oci/oci-hook.sock", "OCI hook socket path")
	flag.StringVar(&config.ociHookBin, "oci-hook-bin", "/opt/oci/oci-hook", "OCI hook binary path")
	flag.StringVar(&config.probeAddr, "health-probe-bind-address", ":8081", "The address the probe endpoint binds to.")
	flag.IntVar(&config.grpcConf.Port, "grpc-port", 50051, "gRPC server port")
	flag.BoolVar(&config.grpcConf.MTLSEnabled, "grpc-mtls-enabled", true,
		"Enable mutual TLS between the agent server and clients")
	flag.StringVar(&config.grpcConf.CertDirPath, "grpc-mtls-cert-dir", "",
		"Path to the directory containing the server and ca TLS certificate")
	flag.StringVar(
		&config.logLevel,
		"log-level",
		"info",
		"agent logger level (debug, info, warn, error)",
	)
	flag.StringVar(
		&config.otlpEndpoint,
		"otlp-endpoint",
		os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT"),
		"OTLP gRPC endpoint (defaults to OTEL_EXPORTER_OTLP_ENDPOINT env var, empty = disabled)",
	)
	flag.StringVar(
		&config.otlpCACert,
		"otlp-ca-cert",
		os.Getenv("OTEL_EXPORTER_OTLP_CERTIFICATE"),
		"Path to the CA certificate for verifying the OTLP collector's TLS certificate (defaults to OTEL_EXPORTER_OTLP_CERTIFICATE env var)",
	)
	flag.StringVar(
		&config.otlpClientCert,
		"otlp-client-cert",
		os.Getenv("OTEL_EXPORTER_OTLP_CLIENT_CERTIFICATE"),
		"Path to the client TLS certificate for mTLS with the OTLP collector (defaults to OTEL_EXPORTER_OTLP_CLIENT_CERTIFICATE env var)",
	)
	flag.StringVar(
		&config.otlpClientKey,
		"otlp-client-key",
		os.Getenv("OTEL_EXPORTER_OTLP_CLIENT_KEY"),
		"Path to the client TLS key for mTLS with the OTLP collector (defaults to OTEL_EXPORTER_OTLP_CLIENT_KEY env var)",
	)
	flag.StringVar(&config.nodeName, "node-name", os.Getenv("NODE_NAME"),
		"Node name for violation reporting (defaults to NODE_NAME env var)")
	flag.StringVar(&config.otlpProtocol, "otlp-protocol", os.Getenv("OTEL_EXPORTER_OTLP_PROTOCOL"),
		"OTLP protocol (defaults to OTEL_EXPORTER_OTLP_PROTOCOL env var)")
	flag.Parse()
	return config
}

func main() {
	var err error
	config := parseFlags()

	ctx := ctrl.SetupSignalHandler()

	logLevel := slog.LevelInfo
	if err = logLevel.UnmarshalText([]byte(config.logLevel)); err != nil {
		fmt.Fprintf(os.Stderr, "failed to parse log level: %v\n", err)
		os.Exit(1)
	}

	slogHandler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: logLevel})
	slogger := slog.New(slogHandler).With("component", "agent")
	slog.SetDefault(slogger)
	ctrl.SetLogger(logr.FromSlogHandler(slogger.Handler()))

	var eventShutdown func(context.Context) error
	if config.otlpEndpoint != "" {
		var violationLogger otellog.Logger
		violationLogger, eventShutdown, err = events.Init(
			ctx,
			config.otlpEndpoint,
			config.otlpCACert,
			config.otlpClientCert,
			config.otlpClientKey,
			config.otlpProtocol,
		)
		if err != nil {
			slogger.ErrorContext(ctx, "failed to initiate violation event pipeline", "error", err)
			os.Exit(1)
		}
		config.violationLogger = violationLogger
		slogger.InfoContext(ctx, "OTLP telemetry enabled", "endpoint", config.otlpEndpoint)
	}

	// This function blocks if everything is alright.
	if err = startAgent(ctx, slogger, config); err != nil {
		slogger.ErrorContext(ctx, "failed to start agent", "error", err)
		os.Exit(1)
	}

	if eventShutdown != nil {
		if err = eventShutdown(ctx); err != nil {
			slogger.ErrorContext(ctx, "failed to shutdown violation event pipeline", "error", err)
		}
	}
}
