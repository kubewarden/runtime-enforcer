package e2e_test

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"testing"

	"sigs.k8s.io/e2e-framework/klient/conf"
	"sigs.k8s.io/e2e-framework/pkg/env"
	"sigs.k8s.io/e2e-framework/pkg/envconf"
	"sigs.k8s.io/e2e-framework/pkg/envfuncs"
	"sigs.k8s.io/e2e-framework/support/kind"
	"sigs.k8s.io/e2e-framework/third_party/helm"
)

//nolint:gochecknoglobals // provided by e2e-framework
var (
	testEnv              env.Environment
	testLearningSelector = fmt.Sprintf(
		`'learning.namespaceSelector={"matchExpressions":null,"matchLabels":{"%s":"%s"}}'`,
		testNamespaceLabelKey,
		testNamespaceLabelValue,
	)
)

const (
	// at the moment `third_party/helm` doesn't expose a way to check helm errors.
	helmRepoNotFoundString  = "no repo named"
	helmRepoReleaseNotFound = "release: not found"
	// this is possible when helm has no repositories in its index. We hit this in our e2e tests.
	helmNoRepositoriesConfigured = "no repositories configured"

	runtimeEnforcerE2EPrefix    = "run-enf-e2e-"
	runtimeEnforcerNamespace    = runtimeEnforcerE2EPrefix + "runtime-enforcer"
	otelCollectorDeploymentName = "runtime-enforcer-otel-collector"
	testNamespaceLabelKey       = "security.rancher.io/learning"
	testNamespaceLabelValue     = "runtime-enforcer-e2e-test"
)

func useExistingCluster() bool {
	return os.Getenv("E2E_USE_EXISTING_CLUSTER") == "true"
}

func installDependencies() bool {
	return os.Getenv("E2E_SKIP_DEPENDENCIES") != "true"
}

type helmChart struct {
	name          string
	namespace     string
	repoLocalName string
	repoURL       string
	path          string
	helmOptions   []helm.Option
}

func getCharts() []helmChart {
	// The order of the charts is relevant because the installation
	// of certain charts may depend on others being present.
	//
	// There are the charts that are always installed by tests.
	charts := []helmChart{
		{
			name:          "runtime-enforcer",
			namespace:     runtimeEnforcerNamespace,
			repoLocalName: runtimeEnforcerE2EPrefix + "runtime-enforcer-repo",
			// no need of repoURL since this is a local installation
			path: "../../charts/runtime-enforcer/",
			helmOptions: []helm.Option{
				helm.WithArgs("--set", "controller.image.tag=latest"),
				helm.WithArgs("--set", "agent.image.tag=latest"),
				helm.WithArgs("--set", "ociHook.install.image.tag=latest"),
				helm.WithArgs("--set", "debugger.image.tag=latest"),
				helm.WithArgs("--set", "debugger.enabled=true"),
				// we need to reduce the timeout to see the wp status controller working properly in e2e tests
				helm.WithArgs("--set", "controller.wpStatusUpdateInterval=2s"),
				// All test namespaces will be created with these labels, so that if we want to disable the learning
				// it is enough to not put the label on the namespace.
				helm.WithArgs("--set-json", testLearningSelector),
			},
		},
	}

	// We let the user choose whether to install the dependencies or not.
	if installDependencies() {
		// If we need to install them, we need to prepend them.
		charts = append([]helmChart{
			{
				name:          "cert-manager",
				namespace:     runtimeEnforcerE2EPrefix + "cert-manager",
				repoLocalName: runtimeEnforcerE2EPrefix + "cert-manager-repo",
				repoURL:       "https://charts.jetstack.io",
				path:          "/cert-manager",
				helmOptions: []helm.Option{
					helm.WithArgs("--version", "v1.18.2"),
					helm.WithArgs("--set", "installCRDs=true"),
				},
			},
			{
				name:          "cert-manager-csi-driver",
				namespace:     runtimeEnforcerE2EPrefix + "cert-manager-csi-driver",
				repoLocalName: runtimeEnforcerE2EPrefix + "cert-manager-csi-driver-repo",
				repoURL:       "https://charts.jetstack.io",
				path:          "/cert-manager-csi-driver",
				helmOptions: []helm.Option{
					helm.WithArgs("--version", "v0.12.0"),
				},
			},
		}, charts...)
	}
	return charts
}

func TestMain(m *testing.M) {
	charts := getCharts()
	commonSetupFuncs := []env.Func{
		// we uninstall here as a defensive check but nothing should be left behind
		uninstallHelmRepos(charts),
		installHelmRepos(charts),
	}

	commonFinishFuncs := []env.Func{
		uninstallHelmRepos(charts),
	}

	if useExistingCluster() {
		path := conf.ResolveKubeConfigFile()
		cfg := envconf.NewWithKubeConfig(path)
		testEnv = env.NewWithConfig(cfg)
	} else {
		cfg, _ := envconf.NewFromFlags()
		testEnv = env.NewWithConfig(cfg)
		kindClusterName := envconf.RandomName("test-controller-e2e", 32)

		// For the setup we need to prepend the cluster creation and the image load
		commonSetupFuncs = append([]env.Func{
			envfuncs.CreateCluster(kind.NewProvider(), kindClusterName),
			envfuncs.LoadImageToCluster(kindClusterName,
				"ghcr.io/rancher-sandbox/runtime-enforcer/controller:latest",
				"--verbose",
				"--mode",
				"direct"),
			envfuncs.LoadImageToCluster(kindClusterName,
				"ghcr.io/rancher-sandbox/runtime-enforcer/agent:latest",
				"--verbose",
				"--mode",
				"direct"),
			envfuncs.LoadImageToCluster(kindClusterName,
				"ghcr.io/rancher-sandbox/runtime-enforcer/oci-hook-installer:latest",
				"--verbose",
				"--mode",
				"direct"),
			envfuncs.LoadImageToCluster(kindClusterName,
				"ghcr.io/rancher-sandbox/runtime-enforcer/debugger:latest",
				"--verbose",
				"--mode",
				"direct"),
		}, commonSetupFuncs...)

		// For the cleanup we need to prepend the log exporter and append the cluster destruction
		commonFinishFuncs = append([]env.Func{
			envfuncs.ExportClusterLogs(kindClusterName, "./logs"),
		}, commonFinishFuncs...)
		commonFinishFuncs = append(commonFinishFuncs, envfuncs.DestroyCluster(kindClusterName))
	}

	testEnv.Setup(commonSetupFuncs...)
	testEnv.Finish(commonFinishFuncs...)
	os.Exit(testEnv.Run(m))
}

func uninstallHelmRepos(charts []helmChart) env.Func {
	return func(ctx context.Context, config *envconf.Config) (context.Context, error) {
		manager := helm.New(config.KubeconfigFile())
		logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

		// we need to uninstall the chart in reverse order to guarantee dependencies are respected.
		for i := len(charts) - 1; i >= 0; i-- {
			chart := charts[i]
			logger.Info("uninstall helm release if present",
				"name", chart.name,
				"namespace", chart.namespace)
			// First we try to uninstall the chart
			err := manager.RunUninstall(
				helm.WithName(chart.name),
				helm.WithNamespace(chart.namespace),
				helm.WithTimeout(defaultHelmTimeout.String()),
			)
			if err != nil && !strings.Contains(err.Error(), helmRepoReleaseNotFound) {
				logger.Warn("failed to uninstall helm chart release",
					"name", chart.name,
					"namespace", chart.namespace,
					"error", err)
			}

			// Then we try to remove the repo
			logger.Info("remove helm repo if present",
				"repo", chart.repoLocalName,
			)
			err = manager.RunRepo(helm.WithArgs("remove", chart.repoLocalName))
			if err != nil &&
				!strings.Contains(err.Error(), helmRepoNotFoundString) &&
				!strings.Contains(err.Error(), helmNoRepositoriesConfigured) {
				logger.Warn("failed to remove helm repo",
					"repo", chart.repoLocalName,
					"error", err)
			}
		}
		return ctx, nil
	}
}

func installHelmRepos(charts []helmChart) env.Func {
	return func(ctx context.Context, config *envconf.Config) (context.Context, error) {
		manager := helm.New(config.KubeconfigFile())
		logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

		for _, chart := range charts {
			var err error

			// chart.path could be in 2 forms:
			// 1. `/<chart-name>` -> so relative to the repo name. It means we want to install from a remote repo
			// 2. `../<chart-path>` -> so a local path. It means we want to install from a local chart.
			//
			// If it is local we don't need to touch it, if relative we will prepend the local repo name
			chartPath := chart.path
			// If the path starts with `/` it means we want to install from a remote repo
			if strings.HasPrefix(chartPath, "/") {
				// First we try to add the repo.
				if err = manager.RunRepo(helm.WithArgs("add", chart.repoLocalName, chart.repoURL)); err != nil {
					return ctx, fmt.Errorf("failed to add local repo '%s': %w", chart.repoLocalName, err)
				}
				// Update the repo.
				if err = manager.RunRepo(helm.WithArgs("update")); err != nil {
					return ctx, fmt.Errorf("failed to update local repo '%s': %w", chart.repoLocalName, err)
				}
				// The final chart path will be the name of repoLocalName + chartPath
				chartPath = chart.repoLocalName + chartPath
			}

			opts := []helm.Option{
				helm.WithName(chart.name),
				helm.WithNamespace(chart.namespace),
				helm.WithArgs("--create-namespace"),
				helm.WithChart(chartPath),
				helm.WithWait(),
				helm.WithTimeout(defaultHelmTimeout.String()),
			}
			opts = append(opts, chart.helmOptions...)
			logger.Info("installing helm release",
				"path", chartPath,
				"name", chart.name,
				"namespace", chart.namespace,
			)
			if err = manager.RunInstall(opts...); err != nil {
				return ctx, fmt.Errorf("failed to install release '%s': %w", chart.name, err)
			}
		}
		return ctx, nil
	}
}
