package resolver_test

import (
	"testing"

	"github.com/neuvector/runtime-enforcer/internal/resolver"
	"github.com/stretchr/testify/require"
)

func TestParseCgroupsPath(t *testing.T) {
	tests := []struct {
		name     string
		in       string
		expected string
	}{
		{
			// example input taken from a kind cluster with cri-containerd
			name:     "cri-containerd kind cluster",
			in:       "kubelet-kubepods-besteffort-pod83b090de_9676_407c_99aa_d33dc6aa0c0d.slice:cri-containerd:18b2adc8507104e412c946bec11679590801f547eee513fa298054f14fbf4240",
			expected: "/kubelet.slice/kubelet-kubepods.slice/kubelet-kubepods-besteffort.slice/kubelet-kubepods-besteffort-pod83b090de_9676_407c_99aa_d33dc6aa0c0d.slice/cri-containerd-18b2adc8507104e412c946bec11679590801f547eee513fa298054f14fbf4240.scope",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out, err := resolver.ParseCgroupsPath(tt.in)
			require.NoError(t, err)
			require.Equal(t, tt.expected, out)
		})
	}
}

func TestSystemdExpandSlice(t *testing.T) {
	tests := []struct {
		name     string
		in       string
		expected string
	}{
		{
			name:     "cri-containerd kind cluster",
			in:       "kubelet-kubepods-besteffort-pod83b090de_9676_407c_99aa_d33dc6aa0c0d.slice",
			expected: "/kubelet.slice/kubelet-kubepods.slice/kubelet-kubepods-besteffort.slice/kubelet-kubepods-besteffort-pod83b090de_9676_407c_99aa_d33dc6aa0c0d.slice",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out, err := resolver.SystemdExpandSlice(tt.in)
			require.NoError(t, err)
			require.Equal(t, tt.expected, out)
		})
	}
}
