package controller

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/kubewarden/runtime-enforcer/api/v1alpha1"
	"github.com/kubewarden/runtime-enforcer/internal/grpcexporter"
)

type testAgentClientPool struct {
	clients    map[string]grpcexporter.AgentClientAPI
	staleNodes []string
	updateFunc func(context.Context, client.Reader) (map[string]grpcexporter.AgentClientAPI, error)
}

func (p *testAgentClientPool) UpdatePool(
	ctx context.Context,
	reader client.Reader,
) (map[string]grpcexporter.AgentClientAPI, error) {
	if p.updateFunc != nil {
		return p.updateFunc(ctx, reader)
	}
	return p.clients, nil
}

func (p *testAgentClientPool) MarkStaleAgentClient(node string) {
	p.staleNodes = append(p.staleNodes, node)
}

func newStatusSyncClient(t *testing.T, objects ...client.Object) client.WithWatch {
	t.Helper()
	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))
	require.NoError(t, v1alpha1.AddToScheme(scheme))
	return fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&v1alpha1.WorkloadPolicy{}).WithObjects(objects...).Build()
}

func statusSyncPolicy() *v1alpha1.WorkloadPolicy {
	return &v1alpha1.WorkloadPolicy{
		Name:       "policy",
		Namespace:  "default",
		Generation: 3,
		Annotations: map[string]string{
			v1alpha1.ViolationAcknowledgePrefix + "7": "investigated",
			"unrelated": "preserved",
		},
		Spec: v1alpha1.WorkloadPolicySpec{
			Mode: "protect",
			RulesByContainer: map[string]*v1alpha1.WorkloadPolicyRules{
				"app": {Executables: v1alpha1.WorkloadPolicyExecutables{Allowed: []string{"/bin/allowed"}}},
			},
		},
		Status: v1alpha1.WorkloadPolicyStatus{
			ViolationCount:       9,
			ActiveViolationCount: 2,
			Violations: []v1alpha1.ViolationRecord{
				{
					ID:                     7,
					LastObservedTimestamp:  metav1.NewTime(time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)),
					FirstObservedTimestamp: metav1.NewTime(time.Date(2026, 1, 1, 11, 0, 0, 0, time.UTC)),
					Occurrences:            2,
					PodName:                "pod",
					ContainerName:          "app",
					ExecutablePath:         "/bin/blocked",
					NodeName:               "node",
					Action:                 "protect",
					WorkloadName:           "deployment",
					WorkloadKind:           "Deployment",
				},
				{ID: 8, ContainerName: "app", ExecutablePath: "/bin/allowed"},
			},
		},
	}
}

type statusSyncLogExporter struct {
	records  []sdklog.Record
	onExport func()
}

func (e *statusSyncLogExporter) Export(_ context.Context, records []sdklog.Record) error {
	if e.onExport != nil {
		e.onExport()
	}
	for _, record := range records {
		e.records = append(e.records, record.Clone())
	}
	return nil
}

func (e *statusSyncLogExporter) Shutdown(context.Context) error {
	return nil
}

func (e *statusSyncLogExporter) ForceFlush(context.Context) error {
	return nil
}

func recordStatusSyncLogs(t *testing.T, r *WorkloadPolicyStatusSync) *statusSyncLogExporter {
	t.Helper()
	exporter := &statusSyncLogExporter{}
	provider := sdklog.NewLoggerProvider(sdklog.WithProcessor(sdklog.NewSimpleProcessor(exporter)))
	t.Cleanup(func() { require.NoError(t, provider.Shutdown(context.Background())) })
	r.eventLogger = provider.Logger("status-sync-test")
	return exporter
}
