package proposalutils_test

import (
	"context"
	"testing"

	securityv1alpha1 "github.com/kubewarden/runtime-enforcer/api/v1alpha1"
	"github.com/kubewarden/runtime-enforcer/internal/eventhandler/proposalutils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestGetWorkloadPolicyProposalName(t *testing.T) {
	tests := []struct {
		name string // description of this test case
		// Named input parameters for target function.
		kind         string
		resourceName string
		want         string
	}{
		{
			kind:         "Deployment",
			resourceName: "my-deployment",
			want:         "deploy-my-deployment",
		},
		{
			kind:         "ReplicaSet",
			resourceName: "my-replica-set",
			want:         "rs-my-replica-set",
		},
		{
			kind:         "DaemonSet",
			resourceName: "my-daemon-set",
			want:         "ds-my-daemon-set",
		},
		{
			kind:         "StatefulSet",
			resourceName: "my-stateful-set",
			want:         "sts-my-stateful-set",
		},
		{
			kind:         "CronJob",
			resourceName: "my-cron-job",
			want:         "cronjob-my-cron-job",
		},
		{
			kind:         "Job",
			resourceName: "my-job",
			want:         "job-my-job",
		},
		{
			kind:         "UnknownKind",
			resourceName: "my-resource",
			want:         "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := proposalutils.GetWorkloadPolicyProposalName(tt.kind, tt.resourceName)
			if tt.want == "" {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)

			assert.Equal(t, tt.want, got)
		})
	}
}

func TestHasProposalBeenPromoted(t *testing.T) {
	const (
		defaultNamespace = "default"
		proposalName     = "opensuse-deployment"
	)

	tests := []struct {
		name           string
		existingPolicy *securityv1alpha1.WorkloadPolicy
		namespace      string
		proposalName   string
		wantPromoted   bool
	}{
		{
			name:         "returns false when no promoted WorkloadPolicy exists",
			namespace:    defaultNamespace,
			proposalName: proposalName,
			wantPromoted: false,
		},
		{
			name:         "returns true when promoted WorkloadPolicy exists",
			namespace:    defaultNamespace,
			proposalName: proposalName,
			existingPolicy: &securityv1alpha1.WorkloadPolicy{
				Namespace: defaultNamespace,
				Name:      proposalName,
				Labels: map[string]string{
					securityv1alpha1.PolicyPromotedFromLabelKey: proposalName,
				},
			},
			wantPromoted: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scheme := runtime.NewScheme()
			require.NoError(t, securityv1alpha1.AddToScheme(scheme))

			builder := fake.NewClientBuilder().WithScheme(scheme)
			if tt.existingPolicy != nil {
				builder = builder.WithObjects(tt.existingPolicy)
			}
			cl := builder.Build()

			promoted, err := proposalutils.HasProposalBeenPromoted(
				context.Background(),
				cl,
				tt.namespace,
				tt.proposalName,
			)
			require.NoError(t, err)
			assert.Equal(t, tt.wantPromoted, promoted)
		})
	}
}
