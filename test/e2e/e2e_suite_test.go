package e2e_test

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/e2e-framework/klient/conf"
	"sigs.k8s.io/e2e-framework/klient/decoder"
	"sigs.k8s.io/e2e-framework/klient/k8s"
	"sigs.k8s.io/e2e-framework/klient/k8s/resources"
	"sigs.k8s.io/e2e-framework/klient/wait"
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
	otelCollectorDeploymentName = "otel-collector"
	testNamespaceLabelKey       = "runtimeenforcer.kubewarden.io/learning"
	testNamespaceLabelValue     = "runtime-enforcer-e2e-test"

	// The chart does not deploy a collector.
	// The suite applies this manifest before it installs the chart.
	// It is not in testdata, because some tests apply every file in testdata.
	otelCollectorManifestDir = "./manifests"
	otelCollectorManifest    = "otel-collector.yaml"
	otelCollectorPodSelector = "app.kubernetes.io/name=otel-collector,app.kubernetes.io/component=otel-collector"
	otelCollectorDeleteWait  = 2 * time.Minute
	otelCollectorReadyWait   = 3 * time.Minute
)

// otelCollectorEndpoint is the plaintext gRPC endpoint of the e2e collector.
// The http:// scheme turns off TLS in the exporters.
func otelCollectorEndpoint() string {
	return fmt.Sprintf("http://%s.%s.svc.cluster.local:4317", otelCollectorDeploymentName, runtimeEnforcerNamespace)
}

func useExistingCluster() bool {
	return os.Getenv("E2E_USE_EXISTING_CLUSTER") == "true"
}

type helmChart struct {
	name          string
	namespace     string
	repoLocalName string
	repoURL       string
	path          string
	helmOptions   []helm.Option
}

// selectOptionalCharts inspects E2E_DEPENDENCIES and returns the
// optional e2e helm dependencies to install, in canonical install
// order. The "none" value installs nothing; an empty/unset value
// installs all; a comma-separated list installs only the named
// dependencies. Unknown names are silently ignored.
func selectOptionalCharts() []helmChart {
	raw := strings.TrimSpace(os.Getenv("E2E_DEPENDENCIES"))
	var selected []helmChart

	// cert-manager (no prerequisites; install first)
	if hasName(raw, "cert-manager") {
		selected = append(selected, helmChart{
			name:          "cert-manager",
			namespace:     runtimeEnforcerE2EPrefix + "cert-manager",
			repoLocalName: runtimeEnforcerE2EPrefix + "cert-manager-repo",
			repoURL:       "https://charts.jetstack.io",
			path:          "/cert-manager",
			helmOptions: []helm.Option{
				helm.WithArgs("--version", "v1.18.2"),
				helm.WithArgs("--set", "installCRDs=true"),
			},
		})
	}

	// cert-manager-csi-driver (depends on cert-manager; install after)
	if hasName(raw, "cert-manager-csi-driver") {
		selected = append(selected, helmChart{
			name:          "cert-manager-csi-driver",
			namespace:     runtimeEnforcerE2EPrefix + "cert-manager-csi-driver",
			repoLocalName: runtimeEnforcerE2EPrefix + "cert-manager-csi-driver-repo",
			repoURL:       "https://charts.jetstack.io",
			path:          "/cert-manager-csi-driver",
			helmOptions: []helm.Option{
				helm.WithArgs("--version", "v0.12.0"),
			},
		})
	}

	return selected
}

func hasName(env, name string) bool {
	if env == "" {
		return true
	}
	for tok := range strings.SplitSeq(env, ",") {
		if strings.EqualFold(strings.TrimSpace(tok), name) {
			return true
		}
	}
	return false
}

func getCharts() []helmChart {
	// The order of the charts is relevant because the installation
	// of certain charts may depend on others being present.
	//
	// The runtime-enforcer chart is always installed. Optional
	// dependencies are selected declaratively via selectOptionalCharts
	// and prepended so they are installed first.
	charts := selectOptionalCharts()
	return append(charts, helmChart{
		name:          "runtime-enforcer",
		namespace:     runtimeEnforcerNamespace,
		repoLocalName: runtimeEnforcerE2EPrefix + "runtime-enforcer-repo",
		// no need of repoURL since this is a local installation
		path: "../../charts/runtime-enforcer/",
		helmOptions: []helm.Option{
			helm.WithArgs("--set", "controller.image.tag=latest"),
			helm.WithArgs("--set", "agent.image.tag=latest"),
			helm.WithArgs("--set", "debugger.image.tag=latest"),
			helm.WithArgs("--set", "debugger.enabled=true"),
			// we need to reduce the timeout to see the wp status controller working properly in e2e tests
			helm.WithArgs("--set", "controller.wpStatusUpdateInterval=2s"),
			// The suite deploys this collector before it installs the chart.
			helm.WithArgs("--set", "global.otel.endpoint="+otelCollectorEndpoint()),
			// All test namespaces will be created with these labels, so that if we want to disable the learning
			// it is enough to not put the label on the namespace.
			helm.WithArgs("--set-json", testLearningSelector),
		},
	})
}

func TestMain(m *testing.M) {
	// we build kubectl_runtime-enforcer binary to run plugin e2e tests

	charts := getCharts()

	commonSetupFuncs := []env.Func{
		// we uninstall here as a defensive check but nothing should be left behind
		uninstallHelmRepos(charts),
		// The collector must be ready before the runtime enforcer starts,
		// so that the exporters see no connection errors at startup.
		setupOtelCollector(),
		installHelmRepos(charts),
	}

	commonFinishFuncs := []env.Func{
		uninstallHelmRepos(charts),
		teardownOtelCollector(),
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
				"ghcr.io/kubewarden/runtime-enforcer/controller:latest",
				"--verbose",
				"--mode",
				"direct"),
			envfuncs.LoadImageToCluster(kindClusterName,
				"ghcr.io/kubewarden/runtime-enforcer/agent:latest",
				"--verbose",
				"--mode",
				"direct"),
			envfuncs.LoadImageToCluster(kindClusterName,
				"ghcr.io/kubewarden/runtime-enforcer/debugger:latest",
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
		for _, v := range slices.Backward(charts) {
			chart := v
			logger.InfoContext(ctx, "uninstall helm release if present",
				"name", chart.name,
				"namespace", chart.namespace)
			// First we try to uninstall the chart
			err := manager.RunUninstall(
				helm.WithName(chart.name),
				helm.WithNamespace(chart.namespace),
				helm.WithTimeout(defaultHelmTimeout.String()),
			)
			if err != nil && !strings.Contains(err.Error(), helmRepoReleaseNotFound) {
				logger.WarnContext(ctx, "failed to uninstall helm chart release",
					"name", chart.name,
					"namespace", chart.namespace,
					"error", err)
			}

			// Then we try to remove the repo
			logger.InfoContext(ctx, "remove helm repo if present",
				"repo", chart.repoLocalName,
			)
			err = manager.RunRepo(helm.WithArgs("remove", chart.repoLocalName))
			if err != nil &&
				!strings.Contains(err.Error(), helmRepoNotFoundString) &&
				!strings.Contains(err.Error(), helmNoRepositoriesConfigured) {
				logger.WarnContext(ctx, "failed to remove helm repo",
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
					return ctx, fmt.Errorf(
						"failed to add local repo '%s': %w",
						chart.repoLocalName,
						err,
					)
				}
				// Update the repo.
				if err = manager.RunRepo(helm.WithArgs("update")); err != nil {
					return ctx, fmt.Errorf(
						"failed to update local repo '%s': %w",
						chart.repoLocalName,
						err,
					)
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
			logger.InfoContext(ctx, "installing helm release",
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

// otelCollectorObjects decodes the collector manifest into objects in the runtime enforcer namespace.
func otelCollectorObjects(ctx context.Context) ([]k8s.Object, error) {
	return decoder.DecodeAllFiles(
		ctx,
		os.DirFS(otelCollectorManifestDir),
		otelCollectorManifest,
		decoder.MutateNamespace(runtimeEnforcerNamespace),
	)
}

func otelCollectorPods(ctx context.Context, r *resources.Resources) ([]corev1.Pod, error) {
	var pods corev1.PodList
	if err := r.List(ctx, &pods, resources.WithLabelSelector(otelCollectorPodSelector)); err != nil {
		return nil, err
	}
	return pods.Items, nil
}

// deleteOtelCollector deletes the collector objects, if they exist,
// and waits until the objects and every collector pod are gone.
func deleteOtelCollector(ctx context.Context, cfg *envconf.Config) error {
	client, err := cfg.NewClient()
	if err != nil {
		return fmt.Errorf("failed to create the client: %w", err)
	}
	r := client.Resources(runtimeEnforcerNamespace)

	objects, err := otelCollectorObjects(ctx)
	if err != nil {
		return fmt.Errorf("failed to decode the otel collector manifest: %w", err)
	}

	for _, obj := range objects {
		err = r.Delete(ctx, obj, resources.WithDeletePropagation(string(metav1.DeletePropagationForeground)))
		if err != nil && !apierrors.IsNotFound(err) {
			return fmt.Errorf("failed to delete %T %s: %w", obj, obj.GetName(), err)
		}
	}

	err = wait.For(func(ctx context.Context) (bool, error) {
		for _, obj := range objects {
			getErr := r.Get(ctx, obj.GetName(), obj.GetNamespace(), obj)
			if getErr == nil {
				return false, nil
			}
			if !apierrors.IsNotFound(getErr) {
				return false, getErr
			}
		}
		pods, listErr := otelCollectorPods(ctx, r)
		if listErr != nil {
			return false, listErr
		}
		return len(pods) == 0, nil
	}, wait.WithContext(ctx), wait.WithTimeout(otelCollectorDeleteWait))
	if err != nil {
		return fmt.Errorf("otel collector objects and pods are not gone: %w", err)
	}
	return nil
}

// setupOtelCollector deploys a fresh collector and waits until its single pod is ready.
// It first deletes a collector left by an earlier run,
// so that a reused cluster also gets a new pod and the current config.
func setupOtelCollector() env.Func {
	return func(ctx context.Context, cfg *envconf.Config) (context.Context, error) {
		logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

		client, err := cfg.NewClient()
		if err != nil {
			return ctx, fmt.Errorf("failed to create the client: %w", err)
		}
		r := client.Resources(runtimeEnforcerNamespace)

		namespace := &corev1.Namespace{Name: runtimeEnforcerNamespace}
		if err = r.Create(ctx, namespace); err != nil && !apierrors.IsAlreadyExists(err) {
			return ctx, fmt.Errorf("failed to create namespace %s: %w", runtimeEnforcerNamespace, err)
		}

		if err = deleteOtelCollector(ctx, cfg); err != nil {
			return ctx, err
		}

		logger.InfoContext(ctx, "deploying otel collector", "namespace", runtimeEnforcerNamespace)
		if err = createOtelCollector(ctx, r); err != nil {
			return ctx, err
		}

		readyPod, err := waitOtelCollectorReady(ctx, r)
		if err != nil {
			return ctx, err
		}
		logger.InfoContext(ctx, "otel collector ready",
			"pod", readyPod.Name,
			"podUID", string(readyPod.UID),
		)
		return ctx, nil
	}
}

// createOtelCollector creates the objects of the collector manifest.
func createOtelCollector(ctx context.Context, r *resources.Resources) error {
	objects, err := otelCollectorObjects(ctx)
	if err != nil {
		return fmt.Errorf("failed to decode the otel collector manifest: %w", err)
	}
	for _, obj := range objects {
		if err = r.Create(ctx, obj); err != nil {
			return fmt.Errorf("failed to create %T %s: %w", obj, obj.GetName(), err)
		}
	}
	return nil
}

// waitOtelCollectorReady waits until the collector Deployment is available for its current generation
// and exactly one collector pod exists, is not being deleted, and is ready.
// It returns that pod.
func waitOtelCollectorReady(ctx context.Context, r *resources.Resources) (corev1.Pod, error) {
	var readyPod corev1.Pod
	err := wait.For(func(ctx context.Context) (bool, error) {
		var deployment appsv1.Deployment
		if getErr := r.Get(ctx, otelCollectorDeploymentName, runtimeEnforcerNamespace, &deployment); getErr != nil {
			return false, getErr
		}
		if deployment.Status.ObservedGeneration != deployment.Generation ||
			!deploymentAvailable(&deployment) {
			return false, nil
		}

		pods, listErr := otelCollectorPods(ctx, r)
		if listErr != nil {
			return false, listErr
		}
		if len(pods) != 1 || pods[0].DeletionTimestamp != nil || !podReady(&pods[0]) {
			return false, nil
		}
		readyPod = pods[0]
		return true, nil
	}, wait.WithContext(ctx), wait.WithTimeout(otelCollectorReadyWait))
	if err != nil {
		return corev1.Pod{}, fmt.Errorf("otel collector is not ready: %w", err)
	}
	return readyPod, nil
}

// teardownOtelCollector deletes the collector. It keeps the namespace.
func teardownOtelCollector() env.Func {
	return func(ctx context.Context, cfg *envconf.Config) (context.Context, error) {
		return ctx, deleteOtelCollector(ctx, cfg)
	}
}

func deploymentAvailable(deployment *appsv1.Deployment) bool {
	for _, cond := range deployment.Status.Conditions {
		if cond.Type == appsv1.DeploymentAvailable {
			return cond.Status == corev1.ConditionTrue
		}
	}
	return false
}

func podReady(pod *corev1.Pod) bool {
	for _, cond := range pod.Status.Conditions {
		if cond.Type == corev1.PodReady {
			return cond.Status == corev1.ConditionTrue
		}
	}
	return false
}
