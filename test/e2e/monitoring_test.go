package e2e_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	tragonv1alpha1 "github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/neuvector/runtime-enforcement/api/v1alpha1"
	"github.com/neuvector/runtime-enforcement/internal/tetragon"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/ptrace"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"sigs.k8s.io/e2e-framework/klient/decoder"
	"sigs.k8s.io/e2e-framework/klient/k8s"
	"sigs.k8s.io/e2e-framework/klient/k8s/resources"
	"sigs.k8s.io/e2e-framework/klient/wait"
	"sigs.k8s.io/e2e-framework/klient/wait/conditions"
	"sigs.k8s.io/e2e-framework/pkg/envconf"
	"sigs.k8s.io/e2e-framework/pkg/features"
	"sigs.k8s.io/e2e-framework/pkg/types"
)

type ExpectedEvent struct {
	ExecutablePath string
	Action         string
}
type MonitoringTestCase struct {
	Commands       []string
	ExpectedEvents []ExpectedEvent
}

// findPod is a utility function that calls k8s List API to find a pod with
// a specific prefix in a given namespace.
func findPod(ctx context.Context, namespace string, prefix string) (string, error) {
	var err error
	var pods corev1.PodList

	r := ctx.Value(key("client")).(*resources.Resources)

	err = r.WithNamespace(namespace).List(ctx, &pods)
	if err != nil {
		return "", err
	}

	for _, v := range pods.Items {
		if strings.HasPrefix(v.Name, prefix) {
			return v.Name, nil
		}
	}

	return "", errors.New("pod is not found")
}

func waitExpectedEvent(
	ctx context.Context,
	t *testing.T,
	expectedEvent ExpectedEvent,
	expectedMetadata bool,
) error {
	var err error
	var value pcommon.Value
	var ok bool

	otelLogStream := ctx.Value(key("otelLogStream")).(*OtelLogStream)
	expectedNamespace := ctx.Value(key("namespace")).(string)
	expectedPodName := ctx.Value(key("targetPodName")).(string)

	var foundSpan *ptrace.Span

	t.Log("waiting for otel events:", expectedEvent)
	err = otelLogStream.WaitUntil(ctx, DefaultOperationTimeout, func(span *ptrace.Span) (bool, error) {
		value, ok = span.Attributes().Get("proc.exepath")
		if !ok {
			// unexpected event type. ignore it.
			return false, nil
		}
		t.Logf("span: %s, exepath: %s, expected: %s", span.Name(), value.AsString(), expectedEvent)

		if value.Str() != expectedEvent.ExecutablePath {
			// not the file that we expected
			return false, nil
		}

		foundSpan = span
		return true, nil
	})

	value, ok = foundSpan.Attributes().Get("action")
	assert.Equal(t, expectedEvent.Action, value.Str())

	// We've found the span that matches the expected event.
	// Here we optionally verify the container metadata.
	if expectedMetadata {
		value, ok = foundSpan.Attributes().Get("k8s.pod.name")

		assert.True(t, ok)
		assert.Equal(t, expectedPodName, value.Str())

		value, ok = foundSpan.Attributes().Get("k8s.ns.name")

		assert.True(t, ok)
		assert.Equal(t, expectedNamespace, value.Str())
	} else {
		value, ok = foundSpan.Attributes().Get("k8s.pod.name")

		assert.True(t, ok)
		assert.Empty(t, value.Str())

		value, ok = foundSpan.Attributes().Get("k8s.ns.name")

		assert.True(t, ok)
		assert.Empty(t, value.Str())
	}

	return err
}

func verifyExpectedResult(
	ctx context.Context,
	t *testing.T,
	tc MonitoringTestCase,
) {
	var err error
	if len(tc.ExpectedEvents) == 0 {
		return
	}

	for i, expectedEvent := range tc.ExpectedEvents {
		// Due to a known issue in Tetragon, we don't expect the first event will come with container metadata.
		err = waitExpectedEvent(ctx, t, expectedEvent, i != 0)
		require.NoError(t, err, "the otel events should be created as expected")
	}
}

func createWorkloadSecurityPolicy(ctx context.Context, t *testing.T, policy *v1alpha1.WorkloadSecurityPolicy) {
	r := ctx.Value(key("client")).(*resources.Resources)

	// 1. Create the resource and wait for Tetragon policy to be created.
	err := r.Create(ctx, policy)
	require.NoError(t, err, "create policy")

	// 2. Wait until the tetragon policy is created
	tp := tragonv1alpha1.TracingPolicyNamespaced{
		ObjectMeta: metav1.ObjectMeta{
			Name:      policy.Name,
			Namespace: policy.Namespace,
		},
	}

	err = wait.For(conditions.New(r).ResourceMatch(&tp, func(_ k8s.Object) bool {
		return true
	}), wait.WithTimeout(DefaultOperationTimeout))
	require.NoError(t, err)

	// 3. Verify the policy content
	assert.Len(t, "1", len(tp.Spec.KProbes))
	assert.Equal(t, []string{"test-policy"}, tp.Spec.KProbes[0].Tags)
	assert.Equal(t, "[9] test-policy", tp.Spec.KProbes[0].Message)
}

func deleteWorkloadSecurityPolicy(ctx context.Context, t *testing.T, policy *v1alpha1.WorkloadSecurityPolicy) {
	var err error
	r := ctx.Value(key("client")).(*resources.Resources)

	// Delete WorkloadSecurityPolicy
	err = r.Delete(ctx, policy)
	require.NoError(t, err)

	err = wait.For(conditions.New(r).ResourceDeleted(&tragonv1alpha1.TracingPolicyNamespaced{
		ObjectMeta: metav1.ObjectMeta{
			Name:      policy.Name,
			Namespace: policy.Namespace,
		},
	}))
	require.NoError(t, err)
}

func runMonitoringTestCase(
	ctx context.Context,
	t *testing.T,
	tc MonitoringTestCase,
) {
	var err error
	r := ctx.Value(key("client")).(*resources.Resources)
	namespace := ctx.Value(key("namespace")).(string)
	expectedPodName := ctx.Value(key("targetPodName")).(string)

	var stdout, stderr bytes.Buffer

	t.Log("running:", tc.Commands)
	err = r.ExecInPod(
		ctx,
		namespace,
		expectedPodName,
		"ubuntu",
		tc.Commands,
		&stdout,
		&stderr,
	)
	require.NoError(t, err)

	verifyExpectedResult(ctx, t, tc)
}

func getMonitoringTest() types.Feature {
	return features.New("Monitoring").
		Setup(SetupSharedK8sClient).
		Setup(func(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
			workloadNamespace := envconf.RandomName("monitoring-namespace", 32)

			t.Log("creating test namespace")
			r := ctx.Value(key("client")).(*resources.Resources)

			namespace := corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: workloadNamespace}}

			err := r.Create(ctx, &namespace)
			require.NoError(t, err, "failed to create test namespace")

			return context.WithValue(ctx, key("namespace"), workloadNamespace)
		}).
		Setup(func(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
			t.Log("setup open telemetry collector")

			var err error
			var otelCollectorPodName string
			otelCollectorPodName, err = findPod(ctx, otelNamespace, "open-telemetry-collector-opentelemetry-collector")
			require.NoError(t, err)
			require.NotEmpty(t, otelCollectorPodName)

			return context.WithValue(ctx, key("otelCollectorPodName"), otelCollectorPodName)
		}).
		Setup(func(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
			t.Log("installing test Ubuntu deployment")

			r := ctx.Value(key("client")).(*resources.Resources)
			namespace := ctx.Value(key("namespace")).(string)

			err := decoder.ApplyWithManifestDir(
				ctx,
				r,
				"./testdata",
				"ubuntu-deployment.yaml",
				[]resources.CreateOption{},
				decoder.MutateNamespace(namespace),
			)
			require.NoError(t, err, "failed to apply test data")

			err = wait.For(
				conditions.New(r).DeploymentAvailable(
					"ubuntu-deployment",
					namespace,
				),
				wait.WithTimeout(DefaultOperationTimeout),
			)
			require.NoError(t, err)

			var ubuntuPodName string

			ubuntuPodName, err = findPod(ctx, namespace, "ubuntu-deployment")
			require.NoError(t, err)
			require.NotEmpty(t, ubuntuPodName)

			return context.WithValue(ctx, key("targetPodName"), ubuntuPodName)
		}).
		Setup(func(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
			t.Log("creating otel log stream for testing")

			var err error
			r := ctx.Value(key("client")).(*resources.Resources)
			otelCollectorPodName := ctx.Value(key("otelCollectorPodName")).(string)

			// We have to create another client because resources.Resources doesn't support pods/logs.
			var clientset *kubernetes.Clientset
			var stream io.ReadCloser

			clientset, err = kubernetes.NewForConfig(r.GetConfig())
			require.NoError(t, err)

			stream, err = clientset.CoreV1().Pods(otelNamespace).
				GetLogs(otelCollectorPodName, &corev1.PodLogOptions{
					Follow: true,
				}).Stream(ctx)

			require.NoError(t, err)

			var otelLogStream *OtelLogStream
			otelLogStream, err = NewOtelLogStream(stream)
			require.NoError(t, err)

			// start otel log stream
			go func() {
				assert.NoError(t, otelLogStream.Start(ctx, t))
			}()
			return context.WithValue(ctx, key("otelLogStream"), otelLogStream)
		}).
		Assess("required resources become available", IfRequiredResourcesAreCreated).
		Assess("a namespace-scoped policy can monitor behaviors correctly",
			func(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
				t.Log("create a security policy")
				namespace := ctx.Value(key("namespace")).(string)

				policy := &v1alpha1.WorkloadSecurityPolicy{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-policy",
						Namespace: namespace,
					},
					Spec: v1alpha1.WorkloadSecurityPolicySpec{
						Mode: "monitor",
						Rules: v1alpha1.WorkloadSecurityPolicyRules{
							Executables: v1alpha1.WorkloadSecurityPolicyExecutables{
								Allowed: []string{
									"/usr/bin/ls",
									"/usr/bin/bash",
									"/usr/bin/sleep",
								},
								AllowedPrefixes: []string{},
							},
						},
						Severity: 9,
						Message:  "test-policy",
						Tags:     []string{"test-policy"},
					},
				}

				// In the verification logic, the event listed in ExpectedEvents
				// field will be evaluated in the given order.
				testcases := []MonitoringTestCase{
					{
						Commands:       []string{"/usr/bin/ls"},
						ExpectedEvents: []ExpectedEvent{},
					},
					{
						Commands: []string{"/usr/bin/sh", "-c", "/usr/bin/apt update"},
						ExpectedEvents: []ExpectedEvent{
							{
								ExecutablePath: "/usr/bin/dash", // dash is the real executable,
								Action:         string(tetragon.TetragonActionViolation),
							},
							{
								ExecutablePath: "/usr/bin/apt",
								Action:         string(tetragon.TetragonActionViolation),
							},
						},
					},
				}

				createWorkloadSecurityPolicy(ctx, t, policy.DeepCopy())
				for _, tc := range testcases {
					runMonitoringTestCase(ctx, t, tc)
				}
				deleteWorkloadSecurityPolicy(ctx, t, policy.DeepCopy())

				return ctx
			}).
		Teardown(func(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
			t.Log("stop otel log stream")

			otelLogStream := ctx.Value(key("otelLogStream")).(*OtelLogStream)
			otelLogStream.Stop()

			return ctx
		}).
		Teardown(func(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
			t.Log("uninstalling test resources")
			namespace := ctx.Value(key("namespace")).(string)
			r := ctx.Value(key("client")).(*resources.Resources)
			err := decoder.DeleteWithManifestDir(
				ctx,
				r,
				"./testdata",
				"ubuntu-deployment.yaml",
				[]resources.DeleteOption{},
				decoder.MutateNamespace(namespace),
			)
			assert.NoError(t, err, "failed to delete test data")

			return ctx
		}).Feature()
}
