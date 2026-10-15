package resolver

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/kubewarden/runtime-enforcer/internal/bpf"
	"github.com/kubewarden/runtime-enforcer/internal/testutil"
	"github.com/kubewarden/runtime-enforcer/internal/types/policymode"
)

func mockPolicyUpdateBinariesFunc(_ PolicyID, _ []string, _ bpf.PolicyValuesOperation) error {
	return nil
}

func mockPolicySettingsUpdateFunc(_ PolicyID, _ policymode.Mode, _ bool, _ bpf.PolicySettingsOperation) error {
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
		mockPolicySettingsUpdateFunc,
	)
	require.NoError(t, err)
	return r
}
