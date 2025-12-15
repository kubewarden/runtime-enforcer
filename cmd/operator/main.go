package main

import (
	"crypto/tls"
	"flag"
	"fmt"
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
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/metrics/filters"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	"sigs.k8s.io/controller-runtime/pkg/webhook"

	"github.com/go-logr/logr"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"

	securityv1alpha1 "github.com/neuvector/runtime-enforcer/api/v1alpha1"
	"github.com/neuvector/runtime-enforcer/internal/controller"
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
}

func parseArgs(logger logr.Logger, config *Config) {
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
	opts := zap.Options{
		Development: true,
	}
	opts.BindFlags(flag.CommandLine)
	flag.Parse()

	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))

	// if the enable-http2 flag is false (the default), http/2 should be disabled
	// due to its vulnerabilities. More specifically, disabling http/2 will
	// prevent from being vulnerable to the HTTP/2 Stream Cancellation and
	// Rapid Reset CVEs. For more information see:
	// - https://github.com/advisories/GHSA-qppj-fm5r-hxr3
	// - https://github.com/advisories/GHSA-4374-p667-p6c8
	disableHTTP2 := func(c *tls.Config) {
		logger.Info("disabling http/2")
		c.NextProtos = []string{"http/1.1"}
	}

	if !config.enableHTTP2 {
		config.tlsOpts = append(config.tlsOpts, disableHTTP2)
	}
}

func SetupControllers(logger logr.Logger,
	mgr manager.Manager,
	metricsCertWatcher *certwatcher.CertWatcher,
	webhookCertWatcher *certwatcher.CertWatcher,
) error {
	var err error

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

func parseWebhookOptions(logger *logr.Logger, config *Config) (*certwatcher.CertWatcher, []func(*tls.Config)) {
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
			logger.Error(err, "Failed to initialize webhook certificate watcher")
			os.Exit(1)
		}

		webhookTLSOpts = append(webhookTLSOpts, func(config *tls.Config) {
			config.GetCertificate = webhookCertWatcher.GetCertificate
		})
	}

	return webhookCertWatcher, webhookTLSOpts
}

func main() {
	setupLog := ctrl.Log.WithName("setup")

	var config Config
	parseArgs(setupLog, &config)

	scheme := runtime.NewScheme()
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(securityv1alpha1.AddToScheme(scheme))

	// Create watchers for metrics and webhooks certificates
	var metricsCertWatcher *certwatcher.CertWatcher

	webhookCertWatcher, webhookTLSOpts := parseWebhookOptions(&setupLog, &config)
	webhookServer := webhook.NewServer(webhook.Options{
		TLSOpts: webhookTLSOpts,
	})

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
		setupLog.Info("Initializing metrics certificate watcher using provided certificates",
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
			setupLog.Error(err, "to initialize metrics certificate watcher", "error", err)
			os.Exit(1)
		}

		metricsServerOptions.TLSOpts = append(metricsServerOptions.TLSOpts, func(config *tls.Config) {
			config.GetCertificate = metricsCertWatcher.GetCertificate
		})
	}

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

	if err = SetupControllers(setupLog, mgr, metricsCertWatcher, webhookCertWatcher); err != nil {
		setupLog.Error(err, "unable to setup controllers")
		os.Exit(1)
	}

	err = builder.WebhookManagedBy(mgr).
		For(&securityv1alpha1.WorkloadPolicyProposal{}).
		WithDefaulter(&controller.ProposalWebhook{Client: mgr.GetClient()}).
		Complete()
	if err != nil {
		setupLog.Error(err, "unable to create a webhook")
		os.Exit(1)
	}

	setupLog.Info("starting manager")
	if err = mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		setupLog.Error(err, "problem running manager")
		os.Exit(1)
	}
}
