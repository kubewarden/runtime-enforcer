package bpf

import (
	"fmt"
	"os"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kubewarden/runtime-enforcer/internal/types/policymode"
)

// TestForeignRootExec covers vector A. Vector A runs a file on a foreign root
// file system, for example the host root file system through /proc/<pid>/root.
//
// The test does not need a separate container image. The test harness runs each
// workload in a fresh mount namespace (RunInCgroup unshares CLONE_NEWNS). The
// test process stays in its own mount namespace. So the workload execs
// /proc/<test-pid>/root/usr/bin/true, where <test-pid> is the PID of the test
// process. The kernel resolves that file through the mount namespace of the test
// process. That namespace differs from the workload namespace. So
// exec_is_foreign_root classifies the exec as a foreign root. The resolved path
// string is /usr/bin/true.
//
// The test runs as root (sudo -E), so the traversal of /proc/<pid>/root passes
// the ptrace access check.
//
// The resolver test resolver.TestReconcileWP_AllowForeignRootExec covers the Go
// wiring of the ALLOW_FOREIGN_ROOT_EXEC option.
func TestForeignRootExec(t *testing.T) {
	const allowedPath = "/usr/bin/true"

	cases := []struct {
		name         string
		hasPolicy    bool
		mode         policymode.Mode
		allowForeign bool
		channel      ChannelType
		shouldEPERM  bool
		expectEvent  bool
		expectedPath string
	}{
		{
			name:         "learning reports a foreign-root exec with an empty path",
			hasPolicy:    false,
			channel:      learningChannel,
			shouldEPERM:  false,
			expectEvent:  true,
			expectedPath: "",
		},
		{
			name:         "protect denies a foreign-root exec even when the path is allow-listed",
			hasPolicy:    true,
			mode:         policymode.Protect,
			allowForeign: false,
			channel:      monitoringChannel,
			shouldEPERM:  true,
			expectEvent:  true,
			expectedPath: allowedPath,
		},
		{
			name:         "monitor reports but allows a foreign-root exec",
			hasPolicy:    true,
			mode:         policymode.Monitor,
			allowForeign: false,
			channel:      monitoringChannel,
			shouldEPERM:  false,
			expectEvent:  true,
			expectedPath: allowedPath,
		},
		{
			name:         "the allow option permits a foreign-root exec with no violation",
			hasPolicy:    true,
			mode:         policymode.Protect,
			allowForeign: true,
			channel:      monitoringChannel,
			shouldEPERM:  false,
			expectEvent:  false,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r, err := newCgroupRunner(t)
			require.NoError(t, err)
			defer r.close()

			if c.hasPolicy {
				const policyID = uint64(60)
				err = r.populatePolicyWithForeign(policyID, c.mode, c.allowForeign, []string{allowedPath})
				require.NoError(t, err)
			}

			// Exec the host /usr/bin/true through the root of the test process.
			// The file lives in the mount namespace of the test process, which
			// differs from the workload namespace, so the exec is a foreign root.
			foreign := fmt.Sprintf("/proc/%d/root%s", os.Getpid(), allowedPath)
			err = r.cgInfo.RunInCgroup(foreign, nil)
			if c.shouldEPERM {
				require.ErrorIs(t, err, syscall.EPERM)
			} else {
				require.NoError(t, err)
			}

			event, err := r.manager.findForeignEventInChannel(c.channel, r.cgInfo.id)
			if c.expectEvent {
				require.NoError(t, err)
				assert.Equal(t, c.expectedPath, event.ExePath)
			} else {
				require.Error(t, err)
			}
		})
	}
}
