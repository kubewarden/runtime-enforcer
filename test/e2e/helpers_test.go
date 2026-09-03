package e2e_test

import (
	"bytes"
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/kubewarden/runtime-enforcer/api/v1alpha1"
	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apimachinerywait "k8s.io/apimachinery/pkg/util/wait"
	"sigs.k8s.io/e2e-framework/klient/decoder"
	"sigs.k8s.io/e2e-framework/klient/k8s"
	"sigs.k8s.io/e2e-framework/klient/k8s/resources"
	"sigs.k8s.io/e2e-framework/klient/wait"
	"sigs.k8s.io/e2e-framework/klient/wait/conditions"
	"sigs.k8s.io/e2e-framework/pkg/envconf"
)

const (
	defaultHelmTimeout         = time.Minute * 5
	defaultImagePullTimeout    = time.Minute * 3
	defaultOperationTimeout    = time.Minute
	testFolder                 = "./testdata"
	opensuseDeploymentManifest = "opensuse-deployment.yaml"
	opensuseDeploymentName     = "opensuse-deployment"
	operationNotPermittedMsg   = "operation not permitted"
)

type key string

func SetupSharedK8sClient(ctx context.Context, t *testing.T, config *envconf.Config) context.Context {
	t.Log("setup shared k8s client")

	r, err := resources.New(config.Client().RESTConfig())
	require.NoError(t, err, "failed to create controller runtime client")

	err = v1alpha1.AddToScheme(r.GetScheme())
	require.NoError(t, err)

	return context.WithValue(ctx, key("client"), r)
}

func IfRequiredResourcesAreCreated(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
	var err error

	r := getClient(ctx)

	err = wait.For(
		conditions.New(r).DeploymentAvailable(
			"runtime-enforcer-controller-manager",
			runtimeEnforcerNamespace,
		),
		wait.WithTimeout(defaultOperationTimeout),
	)
	require.NoError(t, err)

	err = wait.For(conditions.New(r).DaemonSetReady(
		&appsv1.DaemonSet{
			Name:      "runtime-enforcer-agent",
			Namespace: runtimeEnforcerNamespace,
		}),
		wait.WithTimeout(defaultOperationTimeout),
	)
	require.NoError(t, err)
	return ctx
}

func getClient(ctx context.Context) *resources.Resources {
	return ctx.Value(key("client")).(*resources.Resources)
}

func getNamespace(ctx context.Context) string {
	return ctx.Value(key("namespace")).(string)
}

func SetupTestNamespace(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
	t.Helper()
	// RandomName already adds a `-` so we need to trim it from our prefix
	testNamespace := envconf.RandomName(strings.TrimSuffix(runtimeEnforcerE2EPrefix, "-"), 32)
	t.Logf("creating test namespace: %q", testNamespace)
	err := getClient(ctx).Create(ctx, &corev1.Namespace{
		Name: testNamespace,
		Labels: map[string]string{
			testNamespaceLabelKey: testNamespaceLabelValue,
		}})
	require.NoError(t, err, "failed to create test namespace %q", testNamespace)
	return context.WithValue(ctx, key("namespace"), testNamespace)
}

////////////////////
// Workload Policy helpers
////////////////////

func createAndWaitWP(ctx context.Context, t *testing.T, policy *v1alpha1.WorkloadPolicy) {
	t.Helper()
	t.Logf("creating workload policy %q and waiting for it to become Ready", policy.NamespacedName())
	err := getClient(ctx).Create(ctx, policy)
	require.NoError(t, err, "failed to create workload policy %q", policy.NamespacedName())
	waitForWorkloadPolicyStatusToBeUpdated(ctx, t, policy)
}

func deleteAndWaitWP(ctx context.Context, t *testing.T, policy *v1alpha1.WorkloadPolicy) {
	t.Helper()
	t.Logf("deleting workload policy %q and waiting for it to be deleted", policy.NamespacedName())
	err := getClient(ctx).Delete(ctx, policy)
	require.NoError(t, err, "failed to delete workload policy %q", policy.NamespacedName())
	err = wait.For(
		conditions.New(getClient(ctx)).ResourceDeleted(policy),
		wait.WithTimeout(defaultOperationTimeout),
	)
	require.NoError(t, err, "workload policy %q cannot be deleted", policy.NamespacedName())
}

func waitForWorkloadPolicyStatusToBeUpdated(
	ctx context.Context,
	t *testing.T,
	policy *v1alpha1.WorkloadPolicy,
) {
	r := getClient(ctx)
	err := wait.For(conditions.New(r).ResourceMatch(policy, func(obj k8s.Object) bool {
		ps, ok := obj.(*v1alpha1.WorkloadPolicy)
		if !ok {
			return false
		}
		t.Log("checking workloadpolicy status:", ps.Status)
		if ps.Status.ObservedGeneration != ps.Generation {
			return false
		}
		if ps.Status.Phase != v1alpha1.Ready {
			return false
		}
		if len(ps.Status.NodesTransitioning) != 0 {
			return false
		}
		if len(ps.Status.NodesWithIssues) != 0 {
			return false
		}
		return true
	}), wait.WithTimeout(60*time.Second))
	require.NoError(t, err, "workloadpolicy status should be updated to Deployed")
}

////////////////////
// Opensuse deployment helpers
////////////////////

func withPolicy(policyName string) decoder.DecodeOption {
	return decoder.MutateOption(func(obj k8s.Object) error {
		deployment := obj.(*appsv1.Deployment)
		deployment.Spec.Template.Labels[v1alpha1.PolicyLabelKey] = policyName
		return nil
	})
}

func createAndWaitOpensuseDeployment(
	ctx context.Context,
	t *testing.T,
	options ...decoder.DecodeOption,
) {
	t.Helper()
	t.Log("installing test Opensuse deployment")
	namespace := getNamespace(ctx)
	decodeOptions := append([]decoder.DecodeOption{decoder.MutateNamespace(namespace)}, options...)
	err := decoder.ApplyWithManifestDir(
		ctx,
		getClient(ctx),
		testFolder,
		opensuseDeploymentManifest,
		[]resources.CreateOption{},
		decodeOptions...,
	)
	require.NoError(t, err, "failed to create opensuse deployment")

	// Wait for opensuse deployment to become available
	err = wait.For(
		conditions.New(getClient(ctx)).DeploymentAvailable(opensuseDeploymentName, namespace),
		wait.WithTimeout(defaultImagePullTimeout),
	)
	require.NoError(t, err, "opensuse deployment should become available")
}

func deleteOpensuseDeployment(ctx context.Context, t *testing.T) {
	t.Helper()
	t.Log("deleting test Opensuse deployment")
	// With foreground cascading deletion the Deployment resource is only removed
	// once all its owned pods have been terminated, so a single wait on the deployment is enough.
	err := decoder.DeleteWithManifestDir(
		ctx,
		getClient(ctx),
		testFolder,
		opensuseDeploymentManifest,
		[]resources.DeleteOption{
			resources.WithDeletePropagation("Foreground"),
		},
		decoder.MutateNamespace(getNamespace(ctx)),
	)
	require.NoError(t, err, "failed to delete test data")

	waitForOpensuseDeploymentDeleted(ctx, t)
}

func waitForOpensuseDeploymentDeleted(ctx context.Context, t *testing.T) {
	t.Helper()
	t.Log("waiting for Opensuse deployment to be deleted")
	deployment := &appsv1.Deployment{
		Name:      opensuseDeploymentName,
		Namespace: getNamespace(ctx),
	}
	err := wait.For(
		conditions.New(getClient(ctx)).ResourceDeleted(deployment),
		wait.WithTimeout(defaultOperationTimeout),
	)
	require.NoError(t, err, "opensuse deployment should be deleted")
}

func findPodByPrefix(ctx context.Context, namespace string, prefix string) (string, error) {
	var pods corev1.PodList

	err := getClient(ctx).WithNamespace(namespace).List(ctx, &pods)
	if err != nil {
		return "", err
	}

	for _, pod := range pods.Items {
		if strings.HasPrefix(pod.Name, prefix) {
			return pod.Name, nil
		}
	}

	return "", fmt.Errorf("pod with prefix %q not found in namespace %q", prefix, namespace)
}

func findOpensuseDeploymentPod(ctx context.Context) (string, error) {
	return findPodByPrefix(ctx, getNamespace(ctx), opensuseDeploymentName)
}

func execInCurrentNamespace(
	ctx context.Context,
	podName string,
	containerName string,
	command []string,
) (string, string, error) {
	var stdout, stderr bytes.Buffer
	err := getClient(ctx).ExecInPod(
		ctx,
		getNamespace(ctx),
		podName,
		containerName,
		command,
		&stdout,
		&stderr,
	)

	return stdout.String(), stderr.String(), err
}

func requireExecAllowedInCurrentNamespace(
	ctx context.Context,
	t *testing.T,
	podName string,
	containerName string,
	command []string,
) (string, string) {
	t.Helper()
	stdout, stderr, err := execInCurrentNamespace(ctx, podName, containerName, command)
	require.NoError(t, err)
	return stdout, stderr
}

func requireExecBlockedInCurrentNamespace(
	ctx context.Context,
	t *testing.T,
	podName string,
	containerName string,
	command []string,
) {
	t.Helper()
	stdout, stderr, err := execInCurrentNamespace(ctx, podName, containerName, command)
	require.Error(t, err)
	require.Empty(t, stdout)
	require.Contains(t, stderr, operationNotPermittedMsg)
}

func verifyOpensuseLearnedProcesses(values []string) bool {
	return slices.Contains(values, "/usr/bin/bash") &&
		slices.Contains(values, "/usr/bin/ls") &&
		slices.Contains(values, "/usr/bin/sleep")
}

func daemonSetUpToDate(r *resources.Resources, daemonset *appsv1.DaemonSet) apimachinerywait.ConditionWithContextFunc {
	return func(ctx context.Context) (bool, error) {
		if err := r.Get(ctx, daemonset.GetName(), daemonset.GetNamespace(), daemonset); err != nil {
			return false, err
		}
		status := daemonset.Status
		if status.UpdatedNumberScheduled != status.DesiredNumberScheduled {
			return false, nil
		}
		return true, nil
	}
}
