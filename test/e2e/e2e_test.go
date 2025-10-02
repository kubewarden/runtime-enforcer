package e2e_test

import (
	"context"
	"testing"
	"time"

	tragonv1alpha1 "github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/neuvector/runtime-enforcement/api/v1alpha1"
	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/e2e-framework/klient/k8s/resources"
	"sigs.k8s.io/e2e-framework/klient/wait"
	"sigs.k8s.io/e2e-framework/klient/wait/conditions"
	"sigs.k8s.io/e2e-framework/pkg/envconf"
)

const DefaultHelmTimeout = time.Minute * 5
const DefaultOperationTimeout = time.Minute

type key string

func SetupSharedK8sClient(ctx context.Context, t *testing.T, config *envconf.Config) context.Context {
	t.Log("setup shared k8s client")

	r, err := resources.New(config.Client().RESTConfig())
	require.NoError(t, err, "failed to create controller runtime client")

	err = v1alpha1.AddToScheme(r.GetScheme())
	require.NoError(t, err)

	err = tragonv1alpha1.AddToScheme(r.GetScheme())
	require.NoError(t, err)

	return context.WithValue(ctx, key("client"), r)
}

func IfRequiredResourcesAreCreated(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
	var err error

	r := ctx.Value(key("client")).(*resources.Resources)

	err = wait.For(
		conditions.New(r).DeploymentAvailable(
			"runtime-enforcement-controller-manager",
			namespace,
		),
		wait.WithTimeout(DefaultOperationTimeout),
	)
	require.NoError(t, err)

	err = wait.For(conditions.New(r).DaemonSetReady(
		&appsv1.DaemonSet{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "runtime-enforcement-daemon",
				Namespace: namespace,
			},
		}),
		wait.WithTimeout(DefaultOperationTimeout),
	)
	require.NoError(t, err)

	err = wait.For(conditions.New(r).DaemonSetReady(
		&appsv1.DaemonSet{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "tetragon",
				Namespace: namespace,
			},
		}),
		wait.WithTimeout(DefaultOperationTimeout),
	)
	require.NoError(t, err)
	return ctx
}

func TestMainFunctions(t *testing.T) {
	t.Log("test main functionalities")

	testEnv.Test(t, getMainTest())
}

func TestEnforcement(t *testing.T) {
	t.Log("test enforcement")

	testEnv.Test(t, getEnforcementTest())
}

func TestLearning(t *testing.T) {
	t.Log("test learning")

	testEnv.Test(t, getLearningModeTest())
}

func TestMonitoring(t *testing.T) {
	t.Log("test monitoring")

	testEnv.Test(t, getMonitoringTest())
}
