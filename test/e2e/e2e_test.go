package e2e_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
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

func TestInstallation(t *testing.T) {
	t.Log("test installation")

	testEnv.Test(t, getEnforcementTest())
}
