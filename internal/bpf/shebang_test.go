package bpf

import (
	"testing"

	"github.com/kubewarden/runtime-enforcer/internal/types/policymode"
	"github.com/stretchr/testify/require"
)

func TestShebangScript(t *testing.T) {
	runner, err := newCgroupRunner(t)
	require.NoError(t, err, "Failed to create cgroup runner")
	defer runner.close()

	scriptPath, remove, err := generateScriptWithLen(3)
	require.NoError(t, err, "failed to generate temporary script")
	defer remove()

	// When a shebang script is executed, the LSM hook fires for
	// the script but not for the interpreter.
	require.NoError(t, runner.runAndFindCommand(&runCommandArgs{
		command:         scriptPath,
		channel:         learningChannel,
		shouldFindEvent: true,
	}), "script path must be learned via the LSM hook")

	// The interpreter itself must NOT appear as a learned event;
	// only the script path should be emitted.
	require.NoError(t, runner.runAndFindCommand(&runCommandArgs{
		command:         scriptPath,
		channel:         learningChannel,
		expectedPath:    "/usr/bin/true",
		shouldFindEvent: false,
	}), "interpreter must not be learned, only the script path")

	// Once a policy is active, learning events must stop being emitted.
	mockPolicyID := uint64(44)
	err = runner.populatePolicyForRunnerCgroup(mockPolicyID, policymode.Protect, []string{scriptPath})
	require.NoError(t, err)

	require.NoError(t, runner.runAndFindCommand(&runCommandArgs{
		command:         scriptPath,
		channel:         learningChannel,
		shouldFindEvent: false,
	}), "script path must not be learned once a policy is active")

	require.NoError(t, runner.runAndFindCommand(&runCommandArgs{
		command:         scriptPath,
		channel:         monitoringChannel,
		shouldFindEvent: false,
	}), "script must be allowed")

	require.NoError(t, runner.runAndFindCommand(&runCommandArgs{
		command:         scriptPath,
		channel:         monitoringChannel,
		expectedPath:    "/usr/bin/true",
		shouldFindEvent: false,
	}), "/usr/bin/true is not seen ebpf side")
}
