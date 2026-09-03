package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	// Import all Kubernetes client auth plugins (e.g. Azure, GCP, OIDC, etc.)
	// to ensure that exec-entrypoint and run can make use of them.
	_ "k8s.io/client-go/plugin/pkg/client/auth"

	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/certwatcher"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/metrics/filters"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	"sigs.k8s.io/controller-runtime/pkg/webhook"

	"github.com/go-logr/logr"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/klog/v2"

	securityv1alpha1 "github.com/kubewarden/runtime-enforcer/api/v1alpha1"
	"github.com/kubewarden/runtime-enforcer/internal/controller"
	"github.com/kubewarden/runtime-enforcer/internal/customloggers/httpserverlogger"
	"github.com/kubewarden/runtime-enforcer/internal/events"
	"github.com/kubewarden/runtime-enforcer/internal/grpcexporter"
	"github.com/kubewarden/runtime-enforcer/internal/metrics"

	otellog "go.opentelemetry.io/otel/log"
	"go.opentelemetry.io/otel/metric"
	// +kubebuilder:scaffold:imports
)

type Config struct {
	metricsAddr                                      string
	metricsCertPath, metricsCertName, metricsCertKey string
	webhookCertPath, webhookCertName, webhookCertKey string
	enableLeaderElection                             bool
	probeAddr                                        string
	secureMetrics                                    bool
	enableHTTP2                                      bool
	tlsOpts                                          []func(*tls.Config)
	wpStatusSyncConfig                               controller.WorkloadPolicyStatusSyncConfig
	logLevel                                         string
	otlpEndpoint                                     string
	otlpProtocol                                     string
	otlpCACert                                       string
	otlpClientCert                                   string
	otlpClientKey                                    string
}

func parseFlags() Config {
	var config Config
	flag.StringVar(&config.metricsAddr, "metrics-bind-address", "0", "The address the metrics endpoint binds to. "+
		"Use :8443 for HTTPS or :8080 for HTTP, or leave as 0 to disable the metrics service.")
	flag.StringVar(&config.probeAddr, "health-probe-bind-address", ":8081", "The address the probe endpoint binds to.")
	flag.BoolVar(&config.enableLeaderElection, "leader-elect", false,
		"Enable leader election for controller manager. "+
			"Enabling this will ensure there is only one active controller manager.")
	flag.BoolVar(&config.secureMetrics, "metrics-secure", true,
		"If set, the metrics endpoint is served securely via HTTPS. Use --metrics-secure=false to use HTTP instead.")
	flag.StringVar(&config.webhookCertPath, "webhook-cert-path", "",
		"The directory that contains the webhook certificate.")
	flag.StringVar(&config.webhookCertName, "webhook-cert-name", "tls.crt", "The name of the webhook certificate file.")
	flag.StringVar(&config.webhookCertKey, "webhook-cert-key", "tls.key", "The name of the webhook key file.")
	flag.StringVar(&config.metricsCertPath, "metrics-cert-path", "",
		"The directory that contains the metrics server certificate.")
	flag.StringVar(&config.metricsCertName, "metrics-cert-name", "tls.crt",
		"The name of the metrics server certificate file.")
	flag.StringVar(&config.metricsCertKey, "metrics-cert-key", "tls.key", "The name of the metrics server key file.")
	flag.BoolVar(&config.enableHTTP2, "enable-http2", false,
		"If set, HTTP/2 will be enabled for the metrics and webhook servers")
	flag.IntVar(&config.wpStatusSyncConfig.AgentPoolConf.Port,
		"wp-status-reconciler-agent-grpc-port",
		grpcexporter.DefaultAgentPort,
		"The port the agent grpc server listens on.")
	flag.DurationVar(&config.wpStatusSyncConfig.UpdateInterval,
		"wp-status-reconciler-update-interval",
		0,
		"The interval at which the workload policy status reconciler updates the status of WorkloadPolicy resources.")
	flag.StringVar(&config.wpStatusSyncConfig.AgentPoolConf.LabelSelectorString,
		"wp-status-reconciler-agent-label-selector",
		grpcexporter.DefaultAgentLabelSelectorString,
		"The label selector for the agent pods as a comma concatenated string.")
	flag.BoolVar(&config.wpStatusSyncConfig.AgentPoolConf.MTLSEnabled,
		"wp-status-reconciler-agent-grpc-mtls-enabled",
		true,
		"Enable mTLS when dialing the agent gRPC endpoint.")
	flag.StringVar(&config.wpStatusSyncConfig.AgentPoolConf.CertDirPath,
		"wp-status-reconciler-agent-grpc-mtls-cert-dir",
		grpcexporter.DefaultCertDirPath,
		"Path to the directory containing the client and ca TLS certificate.")
	flag.StringVar(
		&config.logLevel,
		"log-level",
		"info",
		"controller logger level (debug, info, warn, error)",
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
	flag.StringVar(&config.otlpProtocol, "otlp-protocol", os.Getenv("OTEL_EXPORTER_OTLP_PROTOCOL"),
		"OTLP protocol (defaults to OTEL_EXPORTER_OTLP_PROTOCOL env var)")
	flag.Parse()

	return config
}

func SetupControllers(logger logr.Logger,
	mgr manager.Manager,
	metricsCertWatcher *certwatcher.CertWatcher,
	webhookCertWatcher *certwatcher.CertWatcher,
	wpStatusSyncConfig *controller.WorkloadPolicyStatusSyncConfig,
) error {
	var err error

	logger.Info("Setting up WorkloadPolicyStatusSync with",
		"config", wpStatusSyncConfig)

	var wpStatusSync *controller.WorkloadPolicyStatusSync
	if wpStatusSync, err = controller.NewWorkloadPolicyStatusSync(
		mgr.GetClient(),
		wpStatusSyncConfig,
	); err != nil {
		return fmt.Errorf("unable to create WorkloadPolicyStatusSync: %w", err)
	}
	if err = mgr.Add(wpStatusSync); err != nil {
		return fmt.Errorf("failed to add WorkloadPolicyStatusSync to controller: %w", err)
	}

	if err = (&controller.WorkloadPolicyProposalReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
	}).SetupWithManager(mgr); err != nil {
		return fmt.Errorf("unable to create WorkloadPolicyProposalReconciler controller: %w", err)
	}
	// +kubebuilder:scaffold:builder

	if metricsCertWatcher != nil {
		logger.Info("Adding metrics certificate watcher to manager")
		if err = mgr.Add(metricsCertWatcher); err != nil {
			logger.Error(err, "unable to add metrics certificate watcher to manager")
			os.Exit(1)
		}
	}

	if webhookCertWatcher != nil {
		logger.Info("Adding webhook certificate watcher to manager")
		if err = mgr.Add(webhookCertWatcher); err != nil {
			logger.Error(err, "unable to add webhook certificate watcher to manager")
			os.Exit(1)
		}
	}

	if err = mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		return fmt.Errorf("unable to create healthz : %w", err)
	}
	if err = mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		return fmt.Errorf("unable to create readyz : %w", err)
	}
	return nil
}

func parseWebhookOptions(logger *slog.Logger, config *Config) (*certwatcher.CertWatcher, []func(*tls.Config)) {
	var webhookCertWatcher *certwatcher.CertWatcher

	// Initial webhook TLS options
	webhookTLSOpts := config.tlsOpts

	if len(config.webhookCertPath) > 0 {
		logger.Info("Initializing webhook certificate watcher using provided certificates",
			"webhook-cert-path",
			config.webhookCertPath,
			"webhook-cert-name",
			config.webhookCertName,
			"webhook-cert-key",
			config.webhookCertKey)

		var err error
		webhookCertWatcher, err = certwatcher.New(
			filepath.Join(config.webhookCertPath, config.webhookCertName),
			filepath.Join(config.webhookCertPath, config.webhookCertKey),
		)
		if err != nil {
			logger.Error("Failed to initialize webhook certificate watcher", "error", err)
			os.Exit(1)
		}

		webhookTLSOpts = append(webhookTLSOpts, func(config *tls.Config) {
			config.GetCertificate = webhookCertWatcher.GetCertificate
		})
	}

	return webhookCertWatcher, webhookTLSOpts
}

func setupHTTP2(logger *slog.Logger, config *Config) {
	// if the enable-http2 flag is false (the default), http/2 should be disabled
	// due to its vulnerabilities. More specifically, disabling http/2 will
	// prevent from being vulnerable to the HTTP/2 Stream Cancellation and
	// Rapid Reset CVEs. For more information see:
	// - https://github.com/advisories/GHSA-qppj-fm5r-hxr3
	// - https://github.com/advisories/GHSA-4374-p667-p6c8
	disableHTTP2Option := func(c *tls.Config) {
		logger.Info("disabling http/2")
		c.NextProtos = []string{"http/1.1"}
	}

	if !config.enableHTTP2 {
		config.tlsOpts = append(config.tlsOpts, disableHTTP2Option)
	}
}

func getMetricsServerOptions(logger *slog.Logger, config *Config) (*certwatcher.CertWatcher, metricsserver.Options) {
	// Create watchers for metrics and webhooks certificates
	var metricsCertWatcher *certwatcher.CertWatcher

	// Metrics endpoint is enabled in 'config/default/kustomization.yaml'. The Metrics options configure the server.
	// More info:
	// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.20.0/pkg/metrics/server
	// - https://book.kubebuilder.io/reference/metrics.html
	metricsServerOptions := metricsserver.Options{
		BindAddress:   config.metricsAddr,
		SecureServing: config.secureMetrics,
		TLSOpts:       config.tlsOpts,
	}

	if config.secureMetrics {
		// FilterProvider is used to protect the metrics endpoint with authn/authz.
		// These configurations ensure that only authorized users and service accounts
		// can access the metrics endpoint. The RBAC are configured in 'config/rbac/kustomization.yaml'. More info:
		// https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.20.0/pkg/metrics/filters#WithAuthenticationAndAuthorization
		metricsServerOptions.FilterProvider = filters.WithAuthenticationAndAuthorization
	}

	// If the certificate is not specified, controller-runtime will automatically
	// generate self-signed certificates for the metrics server. While convenient for development and testing,
	// this setup is not recommended for production.
	//
	// TODO(user): If you enable certManager, uncomment the following lines:
	// - [METRICS-WITH-CERTS] at config/default/kustomization.yaml to generate and use certificates
	// managed by cert-manager for the metrics server.
	// - [PROMETHEUS-WITH-CERTS] at config/prometheus/kustomization.yaml for TLS certification.
	if len(config.metricsCertPath) > 0 {
		logger.Info("Initializing metrics certificate watcher using provided certificates",
			"metrics-cert-path",
			config.metricsCertPath,
			"metrics-cert-name",
			config.metricsCertName,
			"metrics-cert-key",
			config.metricsCertKey)

		var err error
		metricsCertWatcher, err = certwatcher.New(
			filepath.Join(config.metricsCertPath, config.metricsCertName),
			filepath.Join(config.metricsCertPath, config.metricsCertKey),
		)
		if err != nil {
			logger.Error("Failed to initialize metrics certificate watcher", "error", err)
			os.Exit(1)
		}

		metricsServerOptions.TLSOpts = append(metricsServerOptions.TLSOpts, func(config *tls.Config) {
			config.GetCertificate = metricsCertWatcher.GetCertificate
		})
	}
	return metricsCertWatcher, metricsServerOptions
}

func setupOtel(
	ctx context.Context,
	slogger *slog.Logger,
	config *Config,
) (func(context.Context) error, error) {
	if config.otlpEndpoint == "" {
		return func(context.Context) error { return nil }, nil
	}

	var err error
	var eventShutdown, metricShutdown func(context.Context) error
	var eventLogger otellog.Logger
	var activeViolationsGauge metric.Int64Gauge
	var shutdowns []func(context.Context) error

	eventLogger, eventShutdown, err = events.Init(
		ctx,
		config.otlpEndpoint,
		config.otlpCACert,
		config.otlpClientCert,
		config.otlpClientKey,
		config.otlpProtocol,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize otel logs: %w", err)
	}
	config.wpStatusSyncConfig.EventLogger = eventLogger
	shutdowns = append(shutdowns, eventShutdown)

	activeViolationsGauge, metricShutdown, err = metrics.Init(
		ctx,
		config.otlpEndpoint,
		config.otlpCACert,
		config.otlpClientCert,
		config.otlpClientKey,
		config.otlpProtocol,
		config.wpStatusSyncConfig.UpdateInterval,
	)
	if err != nil {
		_ = eventShutdown(ctx)
		return nil, fmt.Errorf("failed to initialize otel metrics: %w", err)
	}
	config.wpStatusSyncConfig.ActiveViolationsGauge = activeViolationsGauge
	shutdowns = append(shutdowns, metricShutdown)

	slogger.InfoContext(ctx, "OTLP telemetry enabled", "endpoint", config.otlpEndpoint)

	return func(shutdownCtx context.Context) error {
		var errs error
		for _, shutdown := range shutdowns {
			if shutdown == nil {
				continue
			}
			if shutdownErr := shutdown(shutdownCtx); shutdownErr != nil {
				errs = errors.Join(errs, shutdownErr)
			}
		}
		return errs
	}, nil
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

	slogHandler := httpserverlogger.NewServerErrorLogHandler(
		slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: logLevel}),
	)

	slogger := slog.New(slogHandler).With("component", "controller")
	slog.SetDefault(slogger)
	ctrlLogger := logr.FromSlogHandler(slogger.Handler())
	ctrl.SetLogger(ctrlLogger)
	klog.SetLogger(ctrlLogger)
	setupLog := ctrlLogger.WithName("setup")

	setupHTTP2(slogger, &config)

	scheme := runtime.NewScheme()
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(securityv1alpha1.AddToScheme(scheme))

	webhookCertWatcher, webhookTLSOpts := parseWebhookOptions(slogger, &config)
	webhookServer := webhook.NewServer(webhook.Options{
		TLSOpts: webhookTLSOpts,
	})

	metricsCertWatcher, metricsServerOptions := getMetricsServerOptions(slogger, &config)

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:                 scheme,
		Metrics:                metricsServerOptions,
		WebhookServer:          webhookServer,
		HealthProbeBindAddress: config.probeAddr,
		LeaderElection:         config.enableLeaderElection,
		LeaderElectionID:       "4e873589.rancher.io",
	})
	if err != nil {
		setupLog.Error(err, "unable to start manager")
		os.Exit(1)
	}

	var otelShutdown func(context.Context) error

	otelShutdown, err = setupOtel(ctx, slogger, &config)
	if err != nil {
		setupLog.Error(err, "failed to setup otel")
		os.Exit(1)
	}

	config.wpStatusSyncConfig.AgentPoolConf.Logger = slog.New(slogHandler).With("component", "agent-pool")
	if err = SetupControllers(
		ctrlLogger, mgr, metricsCertWatcher, webhookCertWatcher, &config.wpStatusSyncConfig,
	); err != nil {
		setupLog.Error(err, "unable to setup controllers")
		os.Exit(1)
	}

	proposalWebhook := &controller.ProposalWebhook{Client: mgr.GetClient()}
	err = builder.WebhookManagedBy(mgr, &securityv1alpha1.WorkloadPolicyProposal{}).
		WithDefaulter(proposalWebhook).
		WithValidator(proposalWebhook).
		Complete()
	if err != nil {
		setupLog.Error(err, "unable to create WorkloadPolicyProposal webhook")
		os.Exit(1)
	}

	err = builder.WebhookManagedBy(mgr, &securityv1alpha1.WorkloadPolicy{}).
		WithValidator(&controller.PolicyCustomValidator{Client: mgr.GetClient()}).
		Complete()
	if err != nil {
		setupLog.Error(err, "unable to create WorkloadPolicy webhook")
		os.Exit(1)
	}

	setupLog.Info("starting manager")
	if err = mgr.Start(ctx); err != nil {
		setupLog.Error(err, "problem running manager")
		os.Exit(1)
	}

	if otelShutdown != nil {
		if err = otelShutdown(ctx); err != nil {
			slogger.ErrorContext(ctx, "failed to shutdown otel telemetry pipeline", "error", err)
		}
	}
}
