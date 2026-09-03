package bpf

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/kubewarden/runtime-enforcer/internal/cgroups"
	"github.com/kubewarden/runtime-enforcer/internal/testutil"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func TestUpdateCgTrackerMap(t *testing.T) {
	cgTrackerMap, err := ebpf.NewMap(&ebpf.MapSpec{
		Type:       ebpf.Hash,
		KeySize:    8, // cgroupID
		ValueSize:  8, // cgroupTrackerID
		MaxEntries: 100,
	})
	require.NoError(t, err)

	// Verify empty path flow
	cgroup1 := uint64(1)
	expectedMap := map[uint64]uint64{
		cgroup1: cgroup1,
	}
	err = UpdateCgTrackerMap(testutil.NewTestLogger(t), cgTrackerMap, cgroup1, "")
	require.NoError(t, err)
	require.Equal(t, expectedMap, dumpMap(cgTrackerMap))

	// Create a mock directory with some subfolders
	tempDir := t.TempDir()

	// name_to_handle_at is not always supported on all machines.
	// For example in our qemu test VMs we face
	// `nameToHandle on /tmp/... failed: operation not supported`
	//
	// In these cases we just skip the nested-cgroup part of the test.
	_, err = cgroups.GetCgroupIDFromPath(tempDir)
	if err != nil && errors.Is(err, unix.EOPNOTSUPP) {
		t.Skipf("name_to_handle_at not supported on %s, skipping test", tempDir)
	}

	nestedPath1 := filepath.Join(tempDir, "nested1")
	nestedPath2 := filepath.Join(tempDir, "nested2")
	nestedPath3 := filepath.Join(tempDir, "nested3")

	require.NoError(t, os.MkdirAll(nestedPath1, 0755))
	require.NoError(t, os.MkdirAll(nestedPath2, 0755))
	require.NoError(t, os.MkdirAll(nestedPath3, 0755))

	expectedNestedCgroup1, err := cgroups.GetCgroupIDFromPath(nestedPath1)
	require.NoError(t, err)
	expectedNestedCgroup2, err := cgroups.GetCgroupIDFromPath(nestedPath2)
	require.NoError(t, err)
	expectedNestedCgroup3, err := cgroups.GetCgroupIDFromPath(nestedPath3)
	require.NoError(t, err)
	expectedMap = map[uint64]uint64{
		cgroup1:               cgroup1,
		expectedNestedCgroup1: cgroup1,
		expectedNestedCgroup2: cgroup1,
		expectedNestedCgroup3: cgroup1,
	}

	err = UpdateCgTrackerMap(testutil.NewTestLogger(t), cgTrackerMap, cgroup1, tempDir)
	require.NoError(t, err)
	require.Equal(t, expectedMap, dumpMap(cgTrackerMap))
}
