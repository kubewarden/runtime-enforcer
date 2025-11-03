package tetragon_test

import (
	"errors"
	"testing"

	tetragonv1 "github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/neuvector/runtime-enforcement/internal/eventhandler"
	"github.com/neuvector/runtime-enforcement/internal/tetragon"
	"github.com/stretchr/testify/require"
)

func TestConvertTetragonProcEvent(t *testing.T) {
	tests := []struct {
		name string
		ev   *tetragonv1.GetEventsResponse
		want *eventhandler.ProcessLearningEvent
	}{

		{
			name: "nil event",
			ev:   nil,
			want: nil,
		},
		{
			name: "no process",
			ev: &tetragonv1.GetEventsResponse{
				Event: &tetragonv1.GetEventsResponse_ProcessExec{
					ProcessExec: nil,
				},
			},
			want: nil,
		},
		{
			name: "no pod",
			ev: &tetragonv1.GetEventsResponse{
				Event: &tetragonv1.GetEventsResponse_ProcessExec{
					ProcessExec: &tetragonv1.ProcessExec{
						Process: &tetragonv1.Process{
							Binary: "/usr/bin/bash",
							Pod:    nil,
						},
					},
				},
			},
			want: nil,
		},
		{
			name: "basic pod info mapped",
			ev: &tetragonv1.GetEventsResponse{
				Event: &tetragonv1.GetEventsResponse_ProcessExec{
					ProcessExec: &tetragonv1.ProcessExec{
						Process: &tetragonv1.Process{
							Binary: "/usr/bin/bash",
							Pod: &tetragonv1.Pod{
								Namespace:    "ns1",
								Workload:     "wl1",
								WorkloadKind: "Deployment",
								Container: &tetragonv1.Container{
									Name: "c1",
								},
							},
						},
					},
				},
			},
			want: &eventhandler.ProcessLearningEvent{
				Namespace:      "ns1",
				ContainerName:  "c1",
				Workload:       "wl1",
				WorkloadKind:   "Deployment",
				ExecutablePath: "/usr/bin/bash",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tetragon.ConvertTetragonProcEvent(tt.ev)
			if tt.want == nil {
				require.Nil(t, got)
				require.Error(t, err)
				if errors.Is(err, tetragon.ErrPodInfoUnavailable) {
					require.Nil(t, tt.ev.GetProcessExec().GetProcess().GetPod())
				}
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.want, got)
		})
	}
}
