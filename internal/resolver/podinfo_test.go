//nolint:testpackage  // we are testing unexported functions
package resolver

import (
	"testing"

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
		want *podInfo
	}{
		{
			name: "nil pod returns nil",
			pod:  nil,
			want: nil,
		},
		{
			name: "standalone pod without GenerateName",
			pod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					UID:       podUID,
					Namespace: "ns1",
					Name:      "mypod",
				},
			},
			want: &podInfo{
				podID:        string(podUID),
				namespace:    "ns1",
				name:         "mypod",
				workloadName: "mypod",
				workloadType: workloadTypePod,
				labels:       map[string]string(nil),
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
			want: &podInfo{
				podID:        string(podUID),
				namespace:    "ns1",
				name:         "mypod-abc123",
				workloadName: "mypod-abc123",
				workloadType: workloadTypePod,
				labels:       map[string]string(nil),
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
			want: &podInfo{
				podID:        string(podUID),
				namespace:    "ns1",
				name:         "runtime-enforcer-controller-manager-6f4b9855c6-5zwq7",
				workloadName: "runtime-enforcer-controller-manager-6f4b9855c6",
				workloadType: workloadTypeReplicaSet,
				labels:       map[string]string{},
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
			want: &podInfo{
				podID:        string(podUID),
				namespace:    "ns1",
				name:         "runtime-enforcer-controller-manager-6f4b9855c6-5zwq7",
				workloadName: "runtime-enforcer-controller-manager", // this is the name of the deployment
				workloadType: workloadTypeDeployment,
				labels: map[string]string{
					podTemplateHashLabel: "6f4b9855c6",
				},
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
			want: &podInfo{
				podID:        string(podUID),
				namespace:    "ns1",
				name:         "dc-pod-1",
				workloadName: "my-dc",
				workloadType: workloadTypeDeploymentConfig,
				labels: map[string]string{
					deploymentConfigLabel: "my-dc",
				},
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
			want: &podInfo{
				podID:        string(podUID),
				namespace:    "ns1",
				name:         "myjob-pod-1",
				workloadName: "myjob",
				workloadType: workloadTypeCronJob,
				labels:       map[string]string(nil),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := getPodInfo(tt.pod)
			require.Equal(t, tt.want, got)
		})
	}
}
