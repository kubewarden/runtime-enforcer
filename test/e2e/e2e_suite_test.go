package e2e_test

import (
	"context"
	"fmt"
	"os"
	"testing"

	"sigs.k8s.io/e2e-framework/pkg/env"
	"sigs.k8s.io/e2e-framework/pkg/envconf"
	"sigs.k8s.io/e2e-framework/pkg/envfuncs"
	"sigs.k8s.io/e2e-framework/support/kind"
	"sigs.k8s.io/e2e-framework/third_party/helm"
)

//nolint:gochecknoglobals // provided by e2e-framework
var (
	testEnv              env.Environment
	kindClusterName      string
	namespace            string
	certManagerNamespace string
	otelNamespace        string
)

const (
	certManagerVersion = "v1.18.2"
	otelVersion        = "v0.136.0"
)

func TestMain(m *testing.M) {
	cfg, _ := envconf.NewFromFlags()
	testEnv = env.NewWithConfig(cfg)
	kindClusterName = envconf.RandomName("test-controller-e2e", 32)
	namespace = envconf.RandomName("enforcer-namespace", 16)
	certManagerNamespace = envconf.RandomName("cert-manager", 16)
	otelNamespace = envconf.RandomName("otel", 16)

	testEnv.Setup(
		envfuncs.CreateCluster(kind.NewProvider(), kindClusterName),
		envfuncs.CreateNamespace(namespace),
		envfuncs.LoadImageToCluster(kindClusterName,
			"ghcr.io/neuvector/runtime-enforcement/operator:latest",
			"--verbose",
			"--mode",
			"direct"),
		envfuncs.LoadImageToCluster(kindClusterName,
			"ghcr.io/neuvector/runtime-enforcement/daemon:latest",
			"--verbose",
			"--mode",
			"direct"),
		InstallOtelCollector(),
		InstallCertManager(),
		InstallRuntimeEnforcement(),
	)

	testEnv.Finish(
		envfuncs.ExportClusterLogs(kindClusterName, "./logs"),
		envfuncs.DeleteNamespace(namespace),
		envfuncs.DestroyCluster(kindClusterName),
	)

	os.Exit(testEnv.Run(m))
}

func InstallCertManager() env.Func {
	return func(ctx context.Context, config *envconf.Config) (context.Context, error) {
		manager := helm.New(config.KubeconfigFile())

		err := manager.RunRepo(helm.WithArgs("add", certManagerNamespace, "https://charts.jetstack.io"))
		if err != nil {
			return ctx, fmt.Errorf("failed to add cert manager repo: %w", err)
		}
		err = manager.RunRepo(helm.WithArgs("update"))
		if err != nil {
			return ctx, fmt.Errorf("failed to update cert manager repo: %w", err)
		}

		// Install cert-manager
		err = manager.RunInstall(
			helm.WithName("cert-manager"),
			helm.WithChart(certManagerNamespace+"/cert-manager"),
			helm.WithNamespace("cert-manager"),
			helm.WithArgs("--create-namespace"),
			helm.WithArgs("--version", certManagerVersion),
			helm.WithArgs("--set", "installCRDs=true"),
			helm.WithWait(),
			helm.WithTimeout(DefaultHelmTimeout.String()))
		if err != nil {
			return ctx, fmt.Errorf("failed to install cert manager: %w", err)
		}

		return ctx, nil
	}
}

func InstallRuntimeEnforcement() env.Func {
	return func(ctx context.Context, config *envconf.Config) (context.Context, error) {
		manager := helm.New(config.KubeconfigFile())
		err := manager.RunInstall(
			helm.WithName("runtime-enforcement"),
			helm.WithNamespace(namespace),
			helm.WithChart("../../charts/runtime-enforcement/"),
			helm.WithArgs("--set", "operator.manager.image.tag=latest"),
			helm.WithArgs("--set", "daemon.daemon.image.tag=latest"),
			helm.WithArgs("--set", "telemetry.mode=custom"),
			helm.WithArgs("--set", "telemetry.tracing=true"),
			helm.WithArgs(
				"--set",
				"telemetry.custom.endpoint=http://open-telemetry-collector-opentelemetry-collector."+otelNamespace+".svc.cluster.local:4317",
			),
			helm.WithArgs("--set", "telemetry.custom.insecure=true"),
			helm.WithWait(),
			helm.WithTimeout(DefaultHelmTimeout.String()),
		)

		if err != nil {
			return ctx, fmt.Errorf("failed to install Tetragon: %w", err)
		}
		return ctx, nil
	}
}

func InstallOtelCollector() env.Func {
	return func(ctx context.Context, config *envconf.Config) (context.Context, error) {
		manager := helm.New(config.KubeconfigFile())

		err := manager.RunRepo(
			helm.WithArgs("add", otelNamespace, "http://open-telemetry.github.io/opentelemetry-helm-charts"),
		)
		if err != nil {
			return ctx, fmt.Errorf("failed to add otel collector repo: %w", err)
		}
		err = manager.RunRepo(helm.WithArgs("update"))
		if err != nil {
			return ctx, fmt.Errorf("failed to update otel collector repo: %w", err)
		}

		// Install otel collector
		err = manager.RunInstall(
			helm.WithName("open-telemetry-collector"),
			helm.WithChart(otelNamespace+"/opentelemetry-collector"),
			helm.WithNamespace(otelNamespace),
			helm.WithArgs("--create-namespace"),
			helm.WithArgs("--version", otelVersion),
			helm.WithArgs("--set image.repository=otel/opentelemetry-collector-k8s"),
			helm.WithArgs("--set mode=deployment"),
			helm.WithArgs("--set config.exporters.file.path=/dev/stdout"),
			helm.WithArgs("--set config.service.pipelines.traces.exporters[0]=file"),
			helm.WithArgs("--set config.service.pipelines.metrics=null"),
			helm.WithArgs("--set config.service.pipelines.logs=null"),
			helm.WithWait(),
			helm.WithTimeout(DefaultHelmTimeout.String()))
		if err != nil {
			return ctx, fmt.Errorf("failed to install otel collector: %w", err)
		}

		return ctx, nil
	}
}
