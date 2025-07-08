package e2e_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"sigs.k8s.io/e2e-framework/pkg/envconf"
	"sigs.k8s.io/e2e-framework/third_party/helm"
)

const DefaultTimeout = time.Minute * 2

type key string

func InstallRuntimeEnforcement(ctx context.Context, t *testing.T, config *envconf.Config) context.Context {
	t.Log("installing runtime-enforcement helm charts")
	manager := helm.New(config.KubeconfigFile())
	err := manager.RunInstall(helm.WithName("runtime-enforcement"),
		helm.WithNamespace(namespace),
		helm.WithChart("../../charts/runtime-enforcement/"),
		helm.WithWait(),
		helm.WithTimeout(DefaultTimeout.String()))

	assert.NoError(t, err, "runtime-enforcement helm chart is not installed correctly")
	return ctx
}

func InstallTetragon(ctx context.Context, t *testing.T, config *envconf.Config) context.Context {
	t.Log("installing tetragon helm charts")
	manager := helm.New(config.KubeconfigFile())

	err := manager.RunRepo(helm.WithArgs("add", ciliumRepo, "https://helm.cilium.io/"))
	require.NoError(t, err, "tetragon repo is not added correctly")

	err = manager.RunRepo(helm.WithArgs("update"))
	require.NoError(t, err, "tetragon repo is not updated correctly")

	err = manager.RunInstall(helm.WithChart(ciliumRepo+"/tetragon"),
		helm.WithName("tetragon"),
		helm.WithNamespace("kube-system"),
		helm.WithArgs("--set", "tetragonOperator.enabled=false", "--set", "crds.installMethod=helm"),
		helm.WithWait(),
		helm.WithTimeout(DefaultTimeout.String()))
	require.NoError(t, err, "tetragon helm chart is not installed correctly")

	return ctx
}

func TestInstallation(t *testing.T) {
	t.Log("test installation")

	testEnv.Test(t, getEnforcementTest())
}
