//nolint:testpackage  // we are testing unexported functions
package podinformer

import (
	"testing"

	"github.com/neuvector/runtime-enforcer/api/v1alpha1"
	"github.com/neuvector/runtime-enforcer/internal/resolver"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

func TestGetPodInfo(t *testing.T) {
	podUID := types.UID("1234-uid")

	tests := []struct {
		name string
		pod  *corev1.Pod
		want *resolver.PodData
	}{
		{
			name: "standalone pod without GenerateName",
			pod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					UID:       podUID,
					Namespace: "ns1",
					Name:      "mypod",
					Labels: map[string]string{
						v1alpha1.PolicyLabelKey: "policy-1",
					},
				},
			},
			want: &resolver.PodData{
				UID:              string(podUID),
				Namespace:        "ns1",
				Name:             "mypod",
				WorkloadName:     "mypod",
				WorkloadType:     workloadTypePod,
				PolicyLabelValue: "policy-1",
			},
		},
		{
			// not sure how realistic this case is, but let's test it anyway
			name: "generated pod without controller",
			pod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					UID:          podUID,
					Namespace:    "ns1",
					Name:         "mypod-abc123",
					GenerateName: "mypod-",
				},
			},
			want: &resolver.PodData{
				UID:          string(podUID),
				Namespace:    "ns1",
				Name:         "mypod-abc123",
				WorkloadName: "mypod-abc123",
				WorkloadType: workloadTypePod,
			},
		},
		{
			name: "generated pod with controller no heuristics met",
			pod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					UID:          podUID,
					Namespace:    "ns1",
					Name:         "runtime-enforcer-controller-manager-6f4b9855c6-5zwq7",
					GenerateName: "runtime-enforcer-controller-manager-6f4b9855c6-",
					Labels:       map[string]string{}, // no label to help with heuristics
					OwnerReferences: []metav1.OwnerReference{{
						Name:       "runtime-enforcer-controller-manager-6f4b9855c6",
						Kind:       workloadTypeReplicaSet,
						Controller: func() *bool { b := true; return &b }(),
					}},
				},
			},
			want: &resolver.PodData{
				UID:          string(podUID),
				Namespace:    "ns1",
				Name:         "runtime-enforcer-controller-manager-6f4b9855c6-5zwq7",
				WorkloadName: "runtime-enforcer-controller-manager-6f4b9855c6",
				WorkloadType: workloadTypeReplicaSet,
			},
		},
		{
			name: "generated pod with controller heuristics met",
			pod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					UID:          podUID,
					Namespace:    "ns1",
					Name:         "runtime-enforcer-controller-manager-6f4b9855c6-5zwq7",
					GenerateName: "runtime-enforcer-controller-manager-6f4b9855c6-",
					Labels: map[string]string{
						podTemplateHashLabel: "6f4b9855c6",
					},
					OwnerReferences: []metav1.OwnerReference{{
						Name:       "runtime-enforcer-controller-manager-6f4b9855c6",
						Kind:       workloadTypeReplicaSet,
						Controller: func() *bool { b := true; return &b }(),
					}},
				},
			},
			want: &resolver.PodData{
				UID:          string(podUID),
				Namespace:    "ns1",
				Name:         "runtime-enforcer-controller-manager-6f4b9855c6-5zwq7",
				WorkloadName: "runtime-enforcer-controller-manager", // this is the name of the deployment
				WorkloadType: workloadTypeDeployment,
			},
		},
		{
			name: "deploymentconfig via replicationcontroller label",
			pod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					UID:          podUID,
					Namespace:    "ns1",
					Name:         "dc-pod-1",
					GenerateName: "dc-pod-",
					Labels: map[string]string{
						deploymentConfigLabel: "my-dc",
					},
					OwnerReferences: []metav1.OwnerReference{{
						Name:       "name",
						Kind:       workloadTypeReplicationController,
						Controller: func() *bool { b := true; return &b }(),
					}},
				},
			},
			want: &resolver.PodData{
				UID:          string(podUID),
				Namespace:    "ns1",
				Name:         "dc-pod-1",
				WorkloadName: "my-dc",
				WorkloadType: workloadTypeDeploymentConfig,
			},
		},
		{
			name: "job controller with cronjob suffix",
			pod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					UID:          podUID,
					Namespace:    "ns1",
					Name:         "myjob-pod-1",
					GenerateName: "myjob-pod-",
					OwnerReferences: []metav1.OwnerReference{{
						Name:       "myjob-12345678",
						Kind:       workloadTypeJob,
						Controller: func() *bool { b := true; return &b }(),
					}},
				},
			},
			want: &resolver.PodData{
				UID:          string(podUID),
				Namespace:    "ns1",
				Name:         "myjob-pod-1",
				WorkloadName: "myjob",
				WorkloadType: workloadTypeCronJob,
			},
		},
		{
			name: "job controller without cronjob suffix",
			pod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					UID:          podUID,
					Namespace:    "ns1",
					Name:         "ubuntu-job-pq2qc",
					GenerateName: "ubuntu-job-",
					OwnerReferences: []metav1.OwnerReference{{
						Name:       "ubuntu-job",
						Kind:       workloadTypeJob,
						Controller: func() *bool { b := true; return &b }(),
					}},
				},
			},
			want: &resolver.PodData{
				UID:          string(podUID),
				Namespace:    "ns1",
				Name:         "ubuntu-job-pq2qc",
				WorkloadName: "ubuntu-job",
				WorkloadType: workloadTypeJob,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := getBasePodData(tt.pod)
			require.Equal(t, tt.want, got)
		})
	}
}
