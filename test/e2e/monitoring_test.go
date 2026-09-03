package e2e_test

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/kubewarden/runtime-enforcer/api/v1alpha1"
	"github.com/kubewarden/runtime-enforcer/internal/types/policymode"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"sigs.k8s.io/e2e-framework/klient/k8s"
	"sigs.k8s.io/e2e-framework/klient/wait"
	"sigs.k8s.io/e2e-framework/klient/wait/conditions"
	"sigs.k8s.io/e2e-framework/pkg/envconf"
	"sigs.k8s.io/e2e-framework/pkg/features"
	"sigs.k8s.io/e2e-framework/pkg/types"
)

func getMonitoringTest() types.Feature {
	return features.New("Monitoring").
		Setup(SetupSharedK8sClient).
		Setup(SetupTestNamespace).
		Setup(setupMonitoringPolicy).
		Setup(setupMonitoringDeployment).
		Assess("required resources become available", IfRequiredResourcesAreCreated).
		Assess("allowed command produces no violation", assessMonitoringAllowedCommand).
		Assess("trigger a violation in monitor mode", assessMonitoringTriggerViolation).
		Assess("violation appears in WorkloadPolicy status", assessMonitoringWaitForViolation).
		Assess("acknowledge the violation via annotation", assessAcknowledgeAnnotate).
		Assess("violation is moved to acknowledged violations", assessAcknowledgeVerify).
		Assess("acknowledge metric appears on the OTEL collector", assessAcknowledgeMetric).
		Teardown(teardownMonitoring).
		Feature()
}

func setupMonitoringPolicy(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
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
}

func setupMonitoringDeployment(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
	createAndWaitOpensuseDeployment(ctx, t, withPolicy("test-policy"))
	opensusePodName, err := findOpensuseDeploymentPod(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, opensusePodName)
	return context.WithValue(ctx, key("targetPodName"), opensusePodName)
}

func assessMonitoringAllowedCommand(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
	targetPodName := ctx.Value(key("targetPodName")).(string)
	t.Log("executing allowed command (should not produce violations)")
	requireExecAllowedInCurrentNamespace(ctx, t, targetPodName, "opensuse", []string{"/usr/bin/ls"})
	return ctx
}

func assessMonitoringTriggerViolation(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
	targetPodName := ctx.Value(key("targetPodName")).(string)
	t.Log("executing disallowed command to trigger violation")
	requireExecAllowedInCurrentNamespace(
		ctx,
		t,
		targetPodName,
		"opensuse",
		[]string{"/usr/bin/sh", "-c", "/usr/bin/zypper refresh"},
	)
	return ctx
}

func assessMonitoringWaitForViolation(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
	targetPodName := ctx.Value(key("targetPodName")).(string)
	r := getClient(ctx)

	policyToCheck := &v1alpha1.WorkloadPolicy{
		Name:      "test-policy",
		Namespace: getNamespace(ctx),
	}

	t.Log("waiting for zypper violation to appear in WorkloadPolicy status")
	err := wait.For(conditions.New(r).ResourceMatch(policyToCheck, func(obj k8s.Object) bool {
		wp, ok := obj.(*v1alpha1.WorkloadPolicy)
		if !ok {
			return false
		}
		for _, v := range wp.Status.Violations {
			if v.ExecutablePath == "/usr/bin/zypper" && v.PodName == targetPodName {
				return true
			}
		}
		return false
	}), wait.WithTimeout(defaultOperationTimeout))
	require.NoError(t, err, "violation for /usr/bin/zypper should appear in WorkloadPolicy status")

	err = r.Get(ctx, "test-policy", getNamespace(ctx), policyToCheck)
	require.NoError(t, err)

	var violationID int64
	var found bool
	for _, v := range policyToCheck.Status.Violations {
		if v.ExecutablePath == "/usr/bin/zypper" {
			assert.Equal(t, policymode.MonitorString, v.Action)
			assert.Equal(t, targetPodName, v.PodName)
			violationID = v.ID
			found = true
			break
		}
	}
	assert.True(t, found, "should find violation record for /usr/bin/zypper")

	return context.WithValue(ctx, key("violationID"), violationID)
}

func assessAcknowledgeAnnotate(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
	r := getClient(ctx)
	violationID := ctx.Value(key("violationID")).(int64)

	policy := &v1alpha1.WorkloadPolicy{
		Name:      "test-policy",
		Namespace: getNamespace(ctx),
	}
	err := r.Get(ctx, "test-policy", getNamespace(ctx), policy)
	require.NoError(t, err)

	if policy.Annotations == nil {
		policy.Annotations = make(map[string]string)
	}
	policy.Annotations[v1alpha1.ViolationAcknowledgePrefix+strconv.FormatInt(violationID, 10)] = "e2e test acknowledgement"

	err = r.Update(ctx, policy)
	require.NoError(t, err, "failed to annotate WorkloadPolicy to acknowledge violation")
	return ctx
}

func assessAcknowledgeVerify(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
	r := getClient(ctx)
	violationID := ctx.Value(key("violationID")).(int64)

	policyToCheck := &v1alpha1.WorkloadPolicy{
		Name:      "test-policy",
		Namespace: getNamespace(ctx),
	}

	t.Log("waiting for violation to appear in acknowledgedViolations")
	err := wait.For(conditions.New(r).ResourceMatch(policyToCheck, func(obj k8s.Object) bool {
		wp, ok := obj.(*v1alpha1.WorkloadPolicy)
		if !ok {
			return false
		}
		for _, av := range wp.Status.AcknowledgedViolations {
			if av.Violation.ID == violationID {
				return true
			}
		}
		return false
	}), wait.WithTimeout(defaultOperationTimeout))
	require.NoError(t, err, "violation should be moved to acknowledgedViolations")

	err = r.Get(ctx, "test-policy", getNamespace(ctx), policyToCheck)
	require.NoError(t, err)

	var found bool
	for _, av := range policyToCheck.Status.AcknowledgedViolations {
		if av.Violation.ID == violationID {
			assert.Equal(t, "e2e test acknowledgement", av.Reason)
			assert.False(t, av.AcknowledgedAt.IsZero(), "acknowledgedAt should be non-zero")
			found = true
			break
		}
	}
	assert.True(t, found, "acknowledged violation record should be present")

	for _, v := range policyToCheck.Status.Violations {
		assert.NotEqual(t, violationID, v.ID, "violation should no longer be in status.violations")
	}

	annotationKey := v1alpha1.ViolationAcknowledgePrefix + strconv.FormatInt(violationID, 10)
	_, annotationPresent := policyToCheck.Annotations[annotationKey]
	assert.False(t, annotationPresent, "acknowledge annotation should be removed after processing")

	return ctx
}

func assessAcknowledgeMetric(ctx context.Context, t *testing.T, config *envconf.Config) context.Context {
	t.Log("querying OTEL collector Prometheus endpoint for acknowledge metric")

	collectorPodName, err := findPodByPrefix(ctx, runtimeEnforcerNamespace, otelCollectorDeploymentName)
	require.NoError(t, err, "should find OTEL collector pod")

	localPort, stopCh, err := portForwardPod(config, runtimeEnforcerNamespace, collectorPodName, 9090)
	require.NoError(t, err, "should port-forward to collector prometheus port")
	defer close(stopCh)

	promURL := fmt.Sprintf("http://localhost:%d/metrics", localPort)

	var metricsBody string
	require.Eventually(t, func() bool {
		body, fetchErr := fetchURL(promURL)
		if fetchErr != nil {
			t.Logf("failed to fetch metrics: %v", fetchErr)
			return false
		}
		metricsBody = body
		return strings.Contains(body, "runtime_enforcer_acknowledge")
	}, defaultOperationTimeout, 2*time.Second,
		"runtime_enforcer_acknowledge metric should appear on the collector Prometheus endpoint",
	)

	t.Log("validating acknowledge metric labels")
	assertMetricHasLabel(t, metricsBody, "runtime_enforcer_acknowledge", "policy_name", "test-policy")
	assertMetricHasLabel(t, metricsBody, "runtime_enforcer_acknowledge", "k8s_namespace_name", getNamespace(ctx))
	assertMetricHasLabel(t, metricsBody, "runtime_enforcer_acknowledge", "action", policymode.MonitorString)
	assertMetricHasLabelKey(t, metricsBody, "runtime_enforcer_acknowledge", "node_name")

	// We acknowledged one violation once, so the counter must be exactly 1.
	// If the count connector also counted policy_violation logs it would be
	// higher, which is what keeps the two metrics apart.
	assertMetricValue(t, metricsBody, "runtime_enforcer_acknowledge", "policy_name", "test-policy", 1)

	return ctx
}

func teardownMonitoring(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
	deleteOpensuseDeployment(ctx, t)
	policy := ctx.Value(key("policy")).(*v1alpha1.WorkloadPolicy)
	deleteAndWaitWP(ctx, t, policy)
	return ctx
}
