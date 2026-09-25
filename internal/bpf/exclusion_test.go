package bpf

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestRuntimeBootstrapExclusion verifies the host-mount-namespace exclusion in
// enforce_cgroup_policy: an exec that runs in the host mount namespace (like the
// OCI runtime bootstrap, e.g. `runc init`) must NOT be reported, while the same
// binary exec'd in a fresh mount namespace (like a real container workload) must
// be reported.
func TestRuntimeBootstrapExclusion(t *testing.T) {
	runner, err := newCgroupRunner(t)
	require.NoError(t, err, "Failed to create cgroup runner")
	defer runner.close()

	// Host mount namespace: mimics the runtime bootstrap. The exclusion should
	// suppress the exec event. We use a binary that is NOT run during manager
	// startup (checkManagerIsStarted runs /usr/bin/true) to avoid matching any
	// leftover startup events.
	require.NoError(t, runner.runAndFindCommand(&runCommandArgs{
		command:         "/usr/bin/who",
		channel:         learningChannel,
		hostMntNs:       true,
		shouldFindEvent: false,
	}), "exec in the host mount namespace must be excluded")

	// Fresh mount namespace: mimics a real container workload. The event must be
	// reported as usual.
	require.NoError(t, runner.runAndFindCommand(&runCommandArgs{
		command:         "/usr/bin/who",
		channel:         learningChannel,
		shouldFindEvent: true,
	}), "exec in a fresh mount namespace must be reported")
}
