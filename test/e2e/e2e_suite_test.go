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
	testEnv         env.Environment
	kindClusterName string
	namespace       string
	certManagerRepo string
)

const (
	certManagerVersion = "v1.18.2"
)

func TestMain(m *testing.M) {
	cfg, _ := envconf.NewFromFlags()
	testEnv = env.NewWithConfig(cfg)
	kindClusterName = envconf.RandomName("test-controller-e2e", 32)
	namespace = envconf.RandomName("enforcer-namespace", 16)
	certManagerRepo = envconf.RandomName("cert-manager", 16)

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

		err := manager.RunRepo(helm.WithArgs("add", certManagerRepo, "https://charts.jetstack.io"))
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
			helm.WithChart(certManagerRepo+"/cert-manager"),
			helm.WithNamespace("cert-manager"),
			helm.WithArgs("--create-namespace"),
			helm.WithArgs("--version", certManagerVersion),
			helm.WithArgs("--set", "installCRDs=true"),
			helm.WithWait(),
			helm.WithTimeout(DefaultTimeout.String()))
		if err != nil {
			return ctx, fmt.Errorf("failed to install cert manager: %w", err)
		}

		return ctx, nil
	}
}

func InstallRuntimeEnforcement() env.Func {
	return func(ctx context.Context, config *envconf.Config) (context.Context, error) {
		manager := helm.New(config.KubeconfigFile())
		err := manager.RunInstall(helm.WithName("runtime-enforcement"),
			helm.WithNamespace(namespace),
			helm.WithChart("../../charts/runtime-enforcement/"),
			helm.WithArgs("--set", "operator.manager.image.tag=latest"),
			helm.WithArgs("--set", "daemon.daemon.image.tag=latest"),
			helm.WithWait(),
			helm.WithTimeout(DefaultTimeout.String()))

		if err != nil {
			return ctx, fmt.Errorf("failed to install Tetragon: %w", err)
		}
		return ctx, nil
	}
}
