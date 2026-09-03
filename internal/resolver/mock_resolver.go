package resolver

import (
	"testing"

	"github.com/kubewarden/runtime-enforcer/internal/bpf"
	"github.com/kubewarden/runtime-enforcer/internal/testutil"
	"github.com/kubewarden/runtime-enforcer/internal/types/policymode"
	"github.com/stretchr/testify/require"
)

func mockPolicyUpdateBinariesFunc(_ PolicyID, _ []string, _ bpf.PolicyValuesOperation) error {
	return nil
}

func mockPolicyModeUpdateFunc(_ PolicyID, _ policymode.Mode, _ bpf.PolicyModeOperation) error {
	return nil
}

func mockCgTrackerUpdateFunc(_ uint64, _ string) error {
	return nil
}

func mockCgroupToPolicyMapUpdateFunc(_ PolicyID, _ []CgroupID, _ bpf.CgroupPolicyOperation) error {
	return nil
}

func NewTestResolver(t testing.TB) *Resolver {
	t.Helper()
	r, err := NewResolver(
		testutil.NewTestLogger(t),
		mockCgTrackerUpdateFunc,
		mockCgroupToPolicyMapUpdateFunc,
		mockPolicyUpdateBinariesFunc,
		mockPolicyModeUpdateFunc,
	)
	require.NoError(t, err)
	return r
}
