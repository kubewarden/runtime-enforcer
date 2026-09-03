package bpf

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kubewarden/runtime-enforcer/internal/types/policymode"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// generateScriptWithLen returns the path of the script and a cleanup function
// The len of the path will 4 + length (4 because of the "/tmp" prefix)
// The caller should call the cleanup function after use.
func generateScriptWithLen(length int) (string, func(), error) {
	// We cannot use `t.TempDir()` because it will generate a directory with
	// a random len and here we care about the len of the final path.
	tmpPath := filepath.Join("/tmp/", strings.Repeat("A", length))
	err := os.WriteFile(tmpPath, []byte("#!/usr/bin/true\n"), 0755)
	return tmpPath, func() {
		// we want to close the file only in case of error.
		if err != nil {
			os.Remove(tmpPath)
		}
	}, err
}

func TestLearning(t *testing.T) {
	runner, err := newCgroupRunner(t)
	require.NoError(t, err, "Failed to create cgroup runner")
	defer runner.close()

	require.NoError(t, runner.runAndFindCommand(&runCommandArgs{
		command:         "/usr/bin/true",
		channel:         learningChannel,
		shouldFindEvent: true,
	}))
}

func TestMemfdBinaryLearning(t *testing.T) {
	runner, err := newCgroupRunner(t)
	require.NoError(t, err, "Failed to create cgroup runner")
	defer runner.close()

	// Create memfd
	name := "memfd_test"
	memfd, err := unix.MemfdCreate(name, unix.MFD_CLOEXEC)
	require.NoError(t, err, "Failed to create memfd")

	memFile := os.NewFile(uintptr(memfd), name)
	require.NotNil(t, memFile, "Failed to create memfd file")
	defer memFile.Close()

	// copy the content of an existing binary inside the memfd
	srcFile, err := os.Open("/usr/bin/true")
	require.NoError(t, err, "Failed to open source file")
	defer srcFile.Close()

	_, err = io.Copy(memFile, srcFile)
	require.NoError(t, err, "Failed to copy data to memfd")

	require.NoError(t, runner.runAndFindCommand(&runCommandArgs{
		command:         fmt.Sprintf("/proc/self/fd/%d", memfd),
		expectedPath:    fmt.Sprintf("/memfd:%s", name),
		channel:         learningChannel,
		shouldFindEvent: true,
	}))
}

func TestMonitorProtectMode(t *testing.T) {
	runner, err := newCgroupRunner(t)
	require.NoError(t, err, "Failed to create cgroup runner")
	defer runner.close()

	//////////////////////
	// Populate the policy map
	//////////////////////
	mockPolicyID := uint64(42)

	// only `pol_str_maps_0` will be popoulated here, all the other maps won't be created.
	err = runner.populatePolicyForRunnerCgroup(mockPolicyID, policymode.Monitor, []string{"/usr/bin/true"})
	require.NoError(t, err, "Failed to populate policy for runner cgroup")

	//////////////////////
	// Try a binary that is allowed
	//////////////////////
	t.Log("Trying allowed binary in monitor mode")
	require.NoError(t, runner.runAndFindCommand(&runCommandArgs{
		command:         "/usr/bin/true",
		channel:         monitoringChannel,
		shouldFindEvent: false,
	}))

	//////////////////////
	// Try a binary that is not allowed
	//////////////////////
	t.Log("Trying not allowed binary in monitor mode")
	require.NoError(t, runner.runAndFindCommand(&runCommandArgs{
		command:         "/usr/bin/who",
		channel:         monitoringChannel,
		shouldFindEvent: true,
	}))

	//////////////////////
	// Try a binary that is not allowed and that is not in `pol_str_maps_0`
	//////////////////////
	t.Log("Write temp binary")
	// we want to test that a binary that falls in a policy map different from pol_str_maps_0
	// will be blocked as well.
	tmpPath, remove, err := generateScriptWithLen(128)
	require.NoError(t, err, "Failed to generate temporary script")
	defer remove()

	// we didn't create a map for a path with this len so we expect this to be reported as not allowed
	t.Log("Trying binary with path len > 128 in monitor mode")
	require.NoError(t, runner.runAndFindCommand(&runCommandArgs{
		command:         tmpPath,
		channel:         monitoringChannel,
		shouldFindEvent: true,
	}))

	//////////////////////
	// Switch to enforcing mode
	//////////////////////
	t.Log("Switching to enforcing mode")
	err = runner.manager.GetPolicyModeUpdateFunc()(mockPolicyID, policymode.Protect, UpdateMode)
	require.NoError(t, err, "Failed to set policy to protect")

	//////////////////////
	// Try a binary that is allowed
	//////////////////////
	// Should behave like the monitor mode
	t.Log("Trying allowed binary in enforcing mode")
	require.NoError(t, runner.runAndFindCommand(&runCommandArgs{
		command:         "/usr/bin/true",
		channel:         monitoringChannel,
		shouldFindEvent: false,
	}))

	//////////////////////
	// Try a binary that is not allowed
	//////////////////////
	t.Log("Trying not allowed binary in enforcing mode")
	require.NoError(t, runner.runAndFindCommand(&runCommandArgs{
		command:         "/usr/bin/who",
		channel:         monitoringChannel,
		shouldFindEvent: true,
		shouldEPERM:     true,
	}))

	//////////////////////
	// Try a binary that is not allowed and that is not in `pol_str_maps_0`
	//////////////////////
	t.Log("Trying binary with path len > 128 in enforcing mode")
	require.NoError(t, runner.runAndFindCommand(&runCommandArgs{
		command:         tmpPath,
		channel:         monitoringChannel,
		shouldEPERM:     true,
		shouldFindEvent: true,
	}))
}

func TestMultiplePolicies(t *testing.T) {
	runner, err := newCgroupRunner(t)
	require.NoError(t, err, "Failed to create cgroup runner")
	defer runner.close()

	mockPolicyID1 := uint64(42)
	err = runner.manager.GetPolicyUpdateBinariesFunc()(mockPolicyID1, []string{"/usr/bin/true"}, AddValuesToPolicy)
	require.NoError(t, err, "Failed to add policy 1 values")

	// We try to create 2 policies to check if `max_entries`
	// for string maps is really greater than 1.
	mockPolicyID2 := uint64(43)
	err = runner.manager.GetPolicyUpdateBinariesFunc()(mockPolicyID2, []string{"/usr/bin/who"}, AddValuesToPolicy)
	require.NoError(t, err, "Failed to add policy 2 values")
}

func TestReplaceValuesNewSizeBucket(t *testing.T) {
	runner, err := newCgroupRunner(t)
	require.NoError(t, err, "Failed to create cgroup runner")
	defer runner.close()

	mockPolicyID := uint64(45)

	// We initially populate `pol_str_maps_0` with `/usr/bin/true`
	err = runner.populatePolicyForRunnerCgroup(mockPolicyID, policymode.Protect, []string{"/usr/bin/true"})
	require.NoError(t, err, "Failed to populate policy for runner cgroup")

	// Now we replace pol_str_maps_0 with a new map that doesn't contain `/usr/bin/true` but contains the path to our script.
	tmpPath, remove, err := generateScriptWithLen(1)
	require.NoError(t, err, "Failed to generate temporary script")
	defer remove()

	err = runner.manager.GetPolicyUpdateBinariesFunc()(
		mockPolicyID,
		[]string{tmpPath},
		ReplaceValuesInPolicy,
	)
	require.NoError(t, err, "ReplaceValuesInPolicy must succeed when adding values in a new size bucket")

	t.Log("Trying allowed binary after replace")
	require.NoError(t, runner.runAndFindCommand(&runCommandArgs{
		command:         tmpPath,
		channel:         monitoringChannel,
		shouldFindEvent: false,
	}), "allowed binary must pass after policy replacement")

	t.Log("Trying disallowed binary after replace")
	require.NoError(t, runner.runAndFindCommand(&runCommandArgs{
		command:         "/usr/bin/true",
		channel:         monitoringChannel,
		shouldFindEvent: true,
		shouldEPERM:     true,
	}), "disallowed binary must be blocked after policy replacement")
}

func TestManagerShutdown(t *testing.T) {
	runner, err := newCgroupRunner(t)
	require.NoError(t, err, "Failed to create cgroup runner")
	defer runner.close()

	err = runner.manager.GetPolicyUpdateBinariesFunc()(

		uint64(100),
		[]string{"/usr/bin/true", "/usr/bin/who"},
		AddValuesToPolicy,
	)
	require.NoError(t, err, "bpf manager should return nil after shutdown")

	err = runner.manager.GetPolicyUpdateBinariesFunc()(
		uint64(100),
		[]string{"/usr/bin/true", "/usr/bin/who"},
		ReplaceValuesInPolicy,
	)
	require.NoError(t, err, "bpf manager should return nil after shutdown")

	err = runner.manager.GetCgroupTrackerUpdateFunc()(
		uint64(200),
		"",
	)
	require.NoError(t, err, "bpf manager should return nil after shutdown")

	err = runner.manager.GetCgroupPolicyUpdateFunc()(
		uint64(100),
		[]uint64{200},
		AddPolicyToCgroups,
	)
	require.NoError(t, err, "bpf manager should return nil after shutdown")

	err = runner.manager.GetCgroupPolicyUpdateFunc()(
		uint64(100),
		[]uint64{200},
		RemovePolicy,
	)

	require.NoError(t, err, "bpf manager should return nil after shutdown")
}
