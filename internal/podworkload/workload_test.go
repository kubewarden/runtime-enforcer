package podworkload

import (
	"strings"
	"testing"

	"github.com/kubewarden/runtime-enforcer/internal/types/workloadkind"
	"github.com/stretchr/testify/require"
)

type podInfo struct {
	name   string
	labels map[string]string
}

func TestGetWorkloadInfo(t *testing.T) {
	tests := []struct {
		name     string
		pod      podInfo
		wantName string
		wantType workloadkind.Kind
	}{
		{
			name: "deployment",
			pod: podInfo{
				name: "ubuntu-deployment-674bcc58f4-pwvps",
				labels: map[string]string{
					podTemplateHashLabel: "674bcc58f4",
				},
			},
			wantName: "ubuntu-deployment",
			wantType: workloadkind.Deployment,
		},
		{
			name: "deployment recognized partial template hash",
			pod: podInfo{
				name: "aaa-" + strings.Repeat("a", 49) + "-674b" + "q8fcg",
				labels: map[string]string{
					podTemplateHashLabel: "674bcc58f4",
				},
			},
			wantName: "aaa-" + strings.Repeat("a", 49),
			wantType: workloadkind.Deployment,
		},
		{
			name: "deployment unrecognized partial template hash",
			pod: podInfo{
				name: "aaa-" + strings.Repeat("a", 50) + "-674" + "q8fcg",
				labels: map[string]string{
					podTemplateHashLabel: "674bcc58f4",
				},
			},
			wantName: "aaa-" + strings.Repeat("a", 50) + "-674" + truncatedSuffix,
			wantType: workloadkind.Deployment,
		},
		{
			name: "deployment no template hash but dash",
			pod: podInfo{
				name: strings.Repeat("a", 57) + "-q8fcg",
				labels: map[string]string{
					podTemplateHashLabel: "674bcc58f4",
				},
			},
			wantName: strings.Repeat("a", 57) + truncatedSuffix,
			wantType: workloadkind.Deployment,
		},
		{
			name: "deployment no template hash",
			pod: podInfo{
				// `-a` is part of the original deployment name not part of the template hash
				name: "aaa-" + strings.Repeat("a", 52) + "-a" + "q8fcg",
				labels: map[string]string{
					podTemplateHashLabel: "674bcc58f4",
				},
			},
			wantName: "aaa-" + strings.Repeat("a", 52) + "-a" + truncatedSuffix,
			wantType: workloadkind.Deployment,
		},
		{
			name: "statefulset",
			pod: podInfo{
				name: "ubuntu-statefulset-0",
				labels: map[string]string{
					"apps.kubernetes.io/pod-index": "0",
					"controller-revision-hash":     "ubuntu-statefulset-7b5845dd9c",
					statefulsetLabel:               "ubuntu-statefulset-0",
				},
			},
			wantName: "ubuntu-statefulset",
			wantType: workloadkind.StatefulSet,
		},
		{
			name: "daemonset",
			pod: podInfo{
				name: "ubuntu-daemonset-6qq8v",
				labels: map[string]string{
					daemonsetLabel:            "568bcd7685",
					"pod-template-generation": "1",
				},
			},
			wantName: "ubuntu-daemonset",
			wantType: workloadkind.DaemonSet,
		},
		{
			name: "daemonset truncated",
			pod: podInfo{
				name: strings.Repeat("a", 58) + "q8fcg",
				labels: map[string]string{
					daemonsetLabel:            "568bcd7685",
					"pod-template-generation": "1",
				},
			},
			wantName: strings.Repeat("a", 58) + truncatedSuffix,
			wantType: workloadkind.DaemonSet,
		},
		{
			name: "daemonset truncated with dash inside",
			pod: podInfo{
				name: "aaa-" + strings.Repeat("a", 54) + "q8fcg",
				labels: map[string]string{
					daemonsetLabel:            "568bcd7685",
					"pod-template-generation": "1",
				},
			},
			wantName: "aaa-" + strings.Repeat("a", 54) + truncatedSuffix,
			wantType: workloadkind.DaemonSet,
		},
		{
			name: "cronjob both label",
			pod: podInfo{
				name: "ubuntu-cronjob-29483273-vthf9",
				labels: map[string]string{
					"batch.kubernetes.io/controller-uid": "0bebfe37-e018-4ff3-86fa-74cdd8dc2c67",
					newJobNameLabel:                      "ubuntu-cronjob-29483273",
					"controller-uid":                     "0bebfe37-e018-4ff3-86fa-74cdd8dc2c67",
					oldJobNameLabel:                      "ubuntu-cronjob-29483273",
				},
			},
			wantName: "ubuntu-cronjob",
			wantType: workloadkind.CronJob,
		},
		{
			name: "cronjob new label only",
			pod: podInfo{
				name: "ubuntu-cronjob-29483273-vthf9",
				labels: map[string]string{
					"batch.kubernetes.io/controller-uid": "0bebfe37-e018-4ff3-86fa-74cdd8dc2c67",
					"controller-uid":                     "0bebfe37-e018-4ff3-86fa-74cdd8dc2c67",
					newJobNameLabel:                      "ubuntu-cronjob-29483273",
				},
			},
			wantName: "ubuntu-cronjob",
			wantType: workloadkind.CronJob,
		},
		{
			name: "cronjob old label only",
			pod: podInfo{
				name: "ubuntu-cronjob-29483273-vthf9",
				labels: map[string]string{
					"batch.kubernetes.io/controller-uid": "0bebfe37-e018-4ff3-86fa-74cdd8dc2c67",
					"controller-uid":                     "0bebfe37-e018-4ff3-86fa-74cdd8dc2c67",
					oldJobNameLabel:                      "ubuntu-cronjob-29483273",
				},
			},
			wantName: "ubuntu-cronjob",
			wantType: workloadkind.CronJob,
		},
		{
			name: "job",
			pod: podInfo{
				name: "ubuntu-job-9bq97",
				labels: map[string]string{
					"batch.kubernetes.io/controller-uid": "bdd392e0-262c-4fdf-8825-6e7d7351fec9",
					newJobNameLabel:                      "ubuntu-job",
					"controller-uid":                     "bdd392e0-262c-4fdf-8825-6e7d7351fec9",
					oldJobNameLabel:                      "ubuntu-job",
				},
			},
			wantName: "ubuntu-job",
			wantType: workloadkind.Job,
		},
		{
			name: "simple pod",
			pod: podInfo{
				name:   "ubuntu-pod",
				labels: map[string]string{},
			},
			wantName: "ubuntu-pod",
			wantType: workloadkind.Pod,
		},
		{
			name: "replicaset ignored",
			pod: podInfo{
				name:   "ubuntu-replicaset-rnswg",
				labels: map[string]string{},
			},
			wantName: "ubuntu-replicaset-rnswg",
			wantType: workloadkind.Pod,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotName, gotType := getWorkloadInfo(tt.pod.name, tt.pod.labels)
			require.Equal(t, tt.wantName, gotName)
			require.Equal(t, tt.wantType, gotType)
		})
	}
}
