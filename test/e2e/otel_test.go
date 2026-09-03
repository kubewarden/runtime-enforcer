package e2e_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/kubewarden/runtime-enforcer/api/v1alpha1"
	"github.com/kubewarden/runtime-enforcer/internal/types/policymode"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/portforward"
	"k8s.io/client-go/transport/spdy"
	"sigs.k8s.io/e2e-framework/klient/k8s"
	"sigs.k8s.io/e2e-framework/klient/k8s/resources"
	"sigs.k8s.io/e2e-framework/klient/wait"
	"sigs.k8s.io/e2e-framework/klient/wait/conditions"
	"sigs.k8s.io/e2e-framework/pkg/envconf"
	"sigs.k8s.io/e2e-framework/pkg/features"
	"sigs.k8s.io/e2e-framework/pkg/types"
)

func getOtelCollectorTest() types.Feature {
	return features.New("OTEL Collector Violation Metrics").
		Setup(SetupSharedK8sClient).
		Setup(SetupTestNamespace).
		Setup(func(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
			policy := &v1alpha1.WorkloadPolicy{
				Name:      "test-policy",
				Namespace: getNamespace(ctx),
				Spec: v1alpha1.WorkloadPolicySpec{
					Mode: policymode.MonitorString,
					RulesByContainer: map[string]*v1alpha1.WorkloadPolicyRules{
						"opensuse": {
							Executables: v1alpha1.WorkloadPolicyExecutables{
								Allowed: []string{
									"/usr/bin/ls",
									"/usr/bin/bash",
									"/usr/bin/sleep",
								},
							},
						},
					},
				},
			}

			createAndWaitWP(ctx, t, policy.DeepCopy())
			return context.WithValue(ctx, key("policy"), policy.DeepCopy())
		}).
		Setup(func(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
			createAndWaitOpensuseDeployment(ctx, t, withPolicy("test-policy"))
			opensusePodName, err := findOpensuseDeploymentPod(ctx)
			require.NoError(t, err)
			require.NotEmpty(t, opensusePodName)
			return context.WithValue(ctx, key("targetPodName"), opensusePodName)
		}).
		Assess("required resources become available", IfRequiredResourcesAreCreated).
		Assess("OTEL collector deployment is ready",
			func(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
				r := getClient(ctx)

				t.Log("waiting for OTEL collector deployment to be available")
				err := wait.For(
					conditions.New(r).DeploymentAvailable(
						otelCollectorDeploymentName,
						runtimeEnforcerNamespace,
					),
					wait.WithTimeout(defaultOperationTimeout),
				)
				require.NoError(t, err, "OTEL collector deployment should be available")

				return ctx
			}).
		Assess("violations produce Prometheus metrics on the collector",
			func(ctx context.Context, t *testing.T, config *envconf.Config) context.Context {
				expectedPodName := ctx.Value(key("targetPodName")).(string)

				t.Log("executing disallowed command to trigger a violation")
				disallowedBinary := "/usr/bin/true"
				requireExecAllowedInCurrentNamespace(
					ctx,
					t,
					expectedPodName,
					"opensuse",
					[]string{disallowedBinary},
				)

				// Wait for the violation to appear in WorkloadPolicy status first.
				// This confirms the gRPC scrape path works and gives the OTEL
				// pipeline enough time to process the event.
				t.Log("waiting for violation to appear in WorkloadPolicy status")
				policyToCheck := ctx.Value(key("policy")).(*v1alpha1.WorkloadPolicy)
				r := getClient(ctx)
				err := wait.For(conditions.New(r).ResourceMatch(policyToCheck, func(obj k8s.Object) bool {
					wp, ok := obj.(*v1alpha1.WorkloadPolicy)
					if !ok || len(wp.Status.Violations) == 0 {
						return false
					}
					for _, v := range wp.Status.Violations {
						if v.ExecutablePath == disallowedBinary &&
							v.Action == policymode.MonitorString &&
							v.PodName == expectedPodName {
							return true
						}
					}
					return false
				}), wait.WithTimeout(defaultOperationTimeout))
				require.NoError(t, err, "violation should appear in WorkloadPolicy status")

				// Now query the OTEL collector Prometheus endpoint for the
				// runtime_enforcer_violations_total metric.
				t.Log("querying OTEL collector Prometheus endpoint for violation metrics")

				collectorPodName, err := findPodByPrefix(ctx, runtimeEnforcerNamespace, otelCollectorDeploymentName)
				require.NoError(t, err, "should find OTEL collector pod")

				localPort, stopCh, err := portForwardPod(
					config, runtimeEnforcerNamespace, collectorPodName, 9090,
				)
				require.NoError(t, err, "should port-forward to collector prometheus port")
				defer close(stopCh)

				promURL := fmt.Sprintf("http://localhost:%d/metrics", localPort)

				// Poll the Prometheus endpoint until the violation metric appears.
				// The OTEL pipeline is asynchronous: the agent batches events, the
				// collector processes them through the count connector and
				// deltatocumulative processor before they appear on /metrics.
				var metricsBody string
				require.Eventually(t, func() bool {
					body, fetchErr := fetchURL(promURL)
					if fetchErr != nil {
						t.Logf("failed to fetch metrics: %v", fetchErr)
						return false
					}
					metricsBody = body
					return strings.Contains(body, "runtime_enforcer_violations")
				}, defaultOperationTimeout, 2*time.Second,
					"runtime_enforcer_violations metric should appear on the collector Prometheus endpoint",
				)

				// Validate the metric has the expected labels from the count
				// connector configuration.
				t.Log("validating metric labels")
				assertMetricHasLabel(t, metricsBody, "runtime_enforcer_violations", "policy_name", "test-policy")
				assertMetricHasLabel(
					t,
					metricsBody,
					"runtime_enforcer_violations",
					"k8s_namespace_name",
					getNamespace(ctx),
				)
				assertMetricHasLabel(t, metricsBody, "runtime_enforcer_violations", "action", policymode.MonitorString)
				// node_name is set dynamically; just verify the label is present.
				assertMetricHasLabelKey(t, metricsBody, "runtime_enforcer_violations", "node_name")
				assertActiveViolationsGauge(ctx, t, r, promURL, policyToCheck)
				return ctx
			}).
		Teardown(func(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
			deleteOpensuseDeployment(ctx, t)
			policy := ctx.Value(key("policy")).(*v1alpha1.WorkloadPolicy)
			deleteAndWaitWP(ctx, t, policy)
			return ctx
		}).Feature()
}

// assertActiveViolationsGauge verifies the runtime_enforcer_active_violations
// gauge exported through the collector matches the policy's current
// status.activeViolationCount and stays bounded to {policy, namespace} labels.
func assertActiveViolationsGauge(
	ctx context.Context,
	t *testing.T,
	r *resources.Resources,
	promURL string,
	policy *v1alpha1.WorkloadPolicy,
) {
	t.Helper()
	const metricName = "runtime_enforcer_active_violations"

	t.Log("validating runtime_enforcer_active_violations gauge matches status.activeViolationCount")
	var body string
	require.Eventually(t, func() bool {
		fetched, fetchErr := fetchURL(promURL)
		if fetchErr != nil {
			return false
		}
		body = fetched

		current := &v1alpha1.WorkloadPolicy{}
		if getErr := r.Get(ctx, policy.GetName(), policy.GetNamespace(), current); getErr != nil {
			return false
		}
		want := current.Status.ActiveViolationCount

		expectedPolicy := fmt.Sprintf(`policy_name="%s"`, policy.GetName())
		expectedNS := fmt.Sprintf(`k8s_namespace_name="%s"`, policy.GetNamespace())

		var got float64
		ok := false
		for line := range strings.SplitSeq(body, "\n") {
			if !strings.HasPrefix(line, metricName) || !strings.Contains(line, expectedPolicy) ||
				!strings.Contains(line, expectedNS) {
				continue
			}
			fields := strings.Fields(line)
			if len(fields) < 2 {
				continue
			}
			value, err := strconv.ParseFloat(fields[len(fields)-1], 64)
			if err != nil {
				continue
			}
			got = value
			ok = true
			break
		}

		return ok && got == float64(want)
	}, defaultOperationTimeout, 2*time.Second,
		"runtime_enforcer_active_violations should match status.activeViolationCount",
	)

	assertMetricHasLabel(t, body, metricName, "policy_name", policy.GetName())
	assertMetricHasLabel(t, body, metricName, "k8s_namespace_name", policy.GetNamespace())
	assertMetricHasNoLabelKey(t, body, metricName, "k8s_pod_name")
	assertMetricHasNoLabelKey(t, body, metricName, "container_name")
	assertMetricHasNoLabelKey(t, body, metricName, "proc_exepath")
}

// portForwardPod creates a port-forward to a pod and returns the local port,
// a stop channel (close to terminate), and any error.
func portForwardPod(
	config *envconf.Config,
	namespace, podName string,
	remotePort int,
) (int, chan struct{}, error) {
	restConfig := config.Client().RESTConfig()

	restClient, err := rest.RESTClientFor(
		&rest.Config{
			Host:                 restConfig.Host,
			TLSClientConfig:      restConfig.TLSClientConfig,
			BearerToken:          restConfig.BearerToken,
			BearerTokenFile:      restConfig.BearerTokenFile,
			APIPath:              "/api",
			GroupVersion:         &schema.GroupVersion{Version: "v1"},
			NegotiatedSerializer: scheme.Codecs.WithoutConversion(),
		},
	)
	if err != nil {
		return 0, nil, fmt.Errorf("creating REST client: %w", err)
	}

	url := restClient.
		Post().
		Resource("pods").
		Namespace(namespace).
		Name(podName).
		SubResource("portforward").
		URL()

	transport, upgrader, err := spdy.RoundTripperFor(restConfig)
	if err != nil {
		return 0, nil, fmt.Errorf("creating round tripper: %w", err)
	}
	dialer := spdy.NewDialer(upgrader, &http.Client{Transport: transport}, http.MethodPost, url)

	stopCh := make(chan struct{})
	readyCh := make(chan struct{})

	// port 0 means "pick a free port"
	ports := []string{fmt.Sprintf("0:%d", remotePort)}
	fw, err := portforward.New(dialer, ports, stopCh, readyCh, io.Discard, io.Discard)
	if err != nil {
		return 0, nil, fmt.Errorf("creating port forwarder: %w", err)
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- fw.ForwardPorts()
	}()

	select {
	case <-readyCh:
	case fwErr := <-errCh:
		return 0, nil, fmt.Errorf("port forward failed: %w", fwErr)
	case <-time.After(10 * time.Second):
		close(stopCh)
		return 0, nil, errors.New("timed out waiting for port forward to be ready")
	}

	forwardedPorts, err := fw.GetPorts()
	if err != nil {
		close(stopCh)
		return 0, nil, fmt.Errorf("getting forwarded ports: %w", err)
	}

	return int(forwardedPorts[0].Local), stopCh, nil
}

// fetchURL performs an HTTP GET and returns the response body as a string.
func fetchURL(url string) (string, error) {
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("unexpected status %d: %s", resp.StatusCode, string(body))
	}

	return string(body), nil
}

// assertMetricHasLabel checks that a Prometheus exposition format body contains
// a metric line with the given label key=value pair.
func assertMetricHasLabel(t *testing.T, body, metricName, labelKey, labelValue string) {
	t.Helper()

	expected := fmt.Sprintf(`%s="%s"`, labelKey, labelValue)
	for line := range strings.SplitSeq(body, "\n") {
		if strings.HasPrefix(line, metricName) && strings.Contains(line, expected) {
			return
		}
	}
	assert.Failf(t, "metric label not found",
		"expected metric %q to have label %s=%q", metricName, labelKey, labelValue)
}

// assertMetricHasLabelKey checks that a Prometheus exposition format body
// contains a metric line with the given label key (any value).
func assertMetricHasLabelKey(t *testing.T, body, metricName, labelKey string) {
	t.Helper()

	needle := labelKey + `="`
	for line := range strings.SplitSeq(body, "\n") {
		if strings.HasPrefix(line, metricName) && strings.Contains(line, needle) {
			return
		}
	}
	assert.Failf(t, "metric label key not found",
		"expected metric %q to have label key %q", metricName, labelKey)
}

// metricValue returns the value of the first sample line for the given metric
// carrying the label key=value pair, or false if there is none. The lines it
// parses are Prometheus exposition format, e.g.
//
//	runtime_enforcer_acknowledge_total{policy_name="test-policy",action="monitor"} 1
//	runtime_enforcer_violations_total{policy_name="test-policy",action="monitor"} 4.2e+07
//
// Sample values are always float-typed there (large counters use scientific
// notation), so we parse them as float64.
func metricValue(body, metricName, labelKey, labelValue string) (float64, bool) {
	expected := fmt.Sprintf(`%s="%s"`, labelKey, labelValue)
	for line := range strings.SplitSeq(body, "\n") {
		if !strings.HasPrefix(line, metricName) || !strings.Contains(line, expected) {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		v, err := strconv.ParseFloat(fields[len(fields)-1], 64)
		if err != nil {
			continue
		}
		return v, true
	}
	return 0, false
}

// assertMetricValue checks that the sample selected by the label key=value pair
// equals the expected value.
func assertMetricValue(t *testing.T, body, metricName, labelKey, labelValue string, expected float64) {
	t.Helper()

	v, ok := metricValue(body, metricName, labelKey, labelValue)
	require.Truef(t, ok,
		"expected metric %q with label %s=%q to be present, body:\n%s",
		metricName, labelKey, labelValue, body)
	assert.InDeltaf(t, expected, v, 0.0001,
		"metric %q with label %s=%q should equal %v", metricName, labelKey, labelValue, expected)
}

// assertMetricHasNoLabelKey checks that no sample line for the given metric
// carries the given label key.
func assertMetricHasNoLabelKey(t *testing.T, body, metricName, labelKey string) {
	t.Helper()

	needle := labelKey + `="`
	for line := range strings.SplitSeq(body, "\n") {
		if strings.HasPrefix(line, metricName) && strings.Contains(line, needle) {
			assert.Failf(t, "unexpected metric label key",
				"metric %q must not carry label key %q, found line: %s", metricName, labelKey, line)
			return
		}
	}
}
