package ocihook

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
)

func startTestAgent(t *testing.T, socketPath string, handle func(net.Conn)) {
	t.Helper()
	require.NoError(t, os.RemoveAll(socketPath))

	var lc net.ListenConfig
	l, err := lc.Listen(t.Context(), "unix", socketPath)
	require.NoError(t, err)

	go func() {
		for {
			c, acceptErr := l.Accept()
			if acceptErr != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				handle(c)
			}(c)
		}
	}()

	t.Cleanup(func() {
		_ = l.Close()
		_ = os.RemoveAll(socketPath)
	})
}

func TestNotify(t *testing.T) {
	t.Run("NotifyAgent success", func(t *testing.T) {
		sock := filepath.Join(t.TempDir(), "notify-ok.sock")
		startTestAgent(t, sock, func(c net.Conn) {
			var req HookRequest
			require.NoError(t, json.NewDecoder(c).Decode(&req))
			require.Equal(t, uint64(1), req.CgroupID)
			require.Equal(t, "/cgroup/path1", req.CgroupPath)
			require.NoError(t, json.NewEncoder(c).Encode(HookResponse{OK: true}))
		})

		err := NotifyAgent(context.Background(), sock, HookRequest{
			CgroupID:   1,
			CgroupPath: "/cgroup/path1",
		})
		require.NoError(t, err)
	})

	t.Run("NotifyAgent agent error", func(t *testing.T) {
		sock := filepath.Join(t.TempDir(), "notify-err.sock")
		startTestAgent(t, sock, func(c net.Conn) {
			var req HookRequest
			require.NoError(t, json.NewDecoder(c).Decode(&req))
			require.NoError(
				t, json.NewEncoder(c).Encode(HookResponse{
					OK:    false,
					Error: "failed to register cgroup",
				}),
			)
		})

		err := NotifyAgent(context.Background(), sock, HookRequest{
			CgroupID:   2,
			CgroupPath: "/cgroup/path2",
		})
		require.Error(t, err)
		require.Contains(t, err.Error(), "agent: failed to register cgroup")
	})

	t.Run("NotifyAgentWithRetry all attempts fail with no listener", func(t *testing.T) {
		sock := filepath.Join(t.TempDir(), "missing.sock")

		err := NotifyAgentWithRetry(
			sock,
			HookRequest{CgroupID: 3, CgroupPath: "/cgroup/path3"},
			DefaultNotifyAgentTimeout,
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), "notify agent failed after")
	})

	t.Run("NotifyAgentWithRetry succeeds after transient failures", func(t *testing.T) {
		sock := filepath.Join(t.TempDir(), "notify-retry.sock")
		var connNum atomic.Int32

		startTestAgent(t, sock, func(c net.Conn) {
			n := connNum.Add(1)
			if n <= 2 {
				// First two connections: close without a JSON response so the client fails on Decode.
				return
			}
			var req HookRequest
			require.NoError(t, json.NewDecoder(c).Decode(&req))
			require.NoError(t, json.NewEncoder(c).Encode(HookResponse{OK: true}))
		})

		err := NotifyAgentWithRetry(
			sock,
			HookRequest{CgroupID: 4, CgroupPath: "/cgroup/path4"},
			DefaultNotifyAgentTimeout,
		)
		require.NoError(t, err)
		require.Equal(t, int32(3), connNum.Load())
	})
}
