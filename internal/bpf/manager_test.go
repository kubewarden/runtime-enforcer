//nolint:testpackage // we are testing unexported functions
package bpf

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/neuvector/runtime-enforcer/internal/cgroups"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"
)

type cgroupInfo struct {
	path string
	fd   int
	id   uint64
}

func (c cgroupInfo) Close() {
	if c.fd > 0 {
		syscall.Close(c.fd)
	}
	if c.path != "" {
		// Cgroups can only be removed if they are empty (no processes inside).
		_ = os.Remove(c.path)
	}
}

func (c cgroupInfo) RunInCgroup(command string, args []string) error {
	cmd := exec.Command(command, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		UseCgroupFD: true,
		CgroupFD:    c.fd,
	}
	return cmd.Run()
}

func createTestCgroup() (cgroupInfo, error) {
	const cgroupRoot = "/sys/fs/cgroup"
	const cgroupName = "my-random-xyz-test-cgroup"
	cgroupPath := filepath.Join(cgroupRoot, cgroupName)

	var err error
	cgInfo := cgroupInfo{}
	defer func() {
		if err != nil {
			cgInfo.Close()
		}
	}()

	err = os.Mkdir(cgroupPath, 0755)
	if err != nil {
		return cgInfo, fmt.Errorf("error creating cgroup: %w", err)
	}
	cgInfo.path = cgroupPath

	fd, err := syscall.Open(cgInfo.path, syscall.O_RDONLY|syscall.O_CLOEXEC, 0)
	if err != nil {
		return cgInfo, fmt.Errorf("error opening cgroup path: %w", err)
	}
	cgInfo.fd = fd

	cgroupID, err := cgroups.GetCgroupIDFromPath(cgInfo.path)
	if err != nil {
		return cgInfo, fmt.Errorf("error getting cgroup ID from path: %w", err)
	}
	cgInfo.id = cgroupID

	return cgInfo, nil
}

type testLogWriter struct {
	t *testing.T
}

func (w *testLogWriter) Write(p []byte) (int, error) {
	// use the formatted output to avoid the new line
	w.t.Logf("%s", string(p))
	return len(p), nil
}

func newTestLogger(t *testing.T) *slog.Logger {
	return slog.New(slog.NewTextHandler(&testLogWriter{t: t}, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	})).With("component", "bpftest")
}

type ChannelType int

const (
	learningChannel ChannelType = iota
	monitoringChannel
)

func (m *Manager) findEventInChannel(ty ChannelType, cgID uint64, command string) error {
	// We chose the channel to extract events from based on the learning flag
	var channel <-chan ProcessEvent
	switch ty {
	case learningChannel:
		channel = m.GetLearningChannel()
	case monitoringChannel:
		channel = m.GetMonitoringChannel()
	default:
		panic("unhandled channel type")
	}

	for {
		select {
		case event := <-channel:
			m.logger.Info("Received event", "event", event)
			if event.CgroupID == cgID &&
				event.CgTrackerID == 0 &&
				event.ExePath == command {
				m.logger.Info("Found event", "event", event)
				return nil
			}
		case <-time.After(1 * time.Second):
			return errors.New("timeout waiting for event")
		}
	}
}

// run it with: go test -v -run TestNoVerifierFailures ./internal/bpf -count=1 -exec "sudo -E".
func TestNoVerifierFailures(t *testing.T) {
	enableLearning := true
	// Loading happens here so we can catch verifier errors without running the manager
	_, err := NewManager(newTestLogger(t), enableLearning, ebpf.LogLevelBranch)
	if err == nil {
		t.Log("BPF manager started successfully :)!!")
		return
	}
	var verr *ebpf.VerifierError
	if errors.As(err, &verr) {
		for _, log := range verr.Log {
			t.Log(log)
		}
	}
	t.FailNow()
}

func TestLearning(t *testing.T) {
	//////////////////////
	// Start BPF manager
	//////////////////////
	enableLearning := true
	manager, err := NewManager(newTestLogger(t), enableLearning, ebpf.LogLevelBranch)
	require.NoError(t, err, "Failed to create BPF manager")
	require.NotNil(t, manager, "BPF manager is nil")

	ctx, cancel := context.WithCancel(context.Background())
	g, ctx := errgroup.WithContext(ctx)
	g.Go(func() error {
		return manager.Start(ctx)
	})
	defer func() {
		cancel()
		require.NoError(t, g.Wait(), "Failed to stop BPF manager")
	}()

	//////////////////////
	// Setup the cgroup
	//////////////////////
	cgInfo, err := createTestCgroup()
	require.NoError(t, err, "Failed to create test cgroup")
	defer cgInfo.Close()

	command := "/usr/bin/true"
	err = cgInfo.RunInCgroup(command, []string{})
	require.NoError(t, err, "Failed to run %s in cgroup", command)

	//////////////////////
	// Get the learning event
	//////////////////////
	err = manager.findEventInChannel(learningChannel, cgInfo.id, command)
	require.NoError(t, err, "Failed to find learning event")
}

func TestMonitoringEnforcing(t *testing.T) {
	//////////////////////
	// Start BPF manager
	//////////////////////
	enableLearning := false
	manager, err := NewManager(newTestLogger(t), enableLearning, ebpf.LogLevelBranch)
	require.NoError(t, err, "Failed to create BPF manager")
	require.NotNil(t, manager, "BPF manager is nil")

	ctx, cancel := context.WithCancel(context.Background())
	g, ctx := errgroup.WithContext(ctx)
	g.Go(func() error {
		return manager.Start(ctx)
	})
	defer func() {
		cancel()
		require.NoError(t, g.Wait(), "Failed to stop BPF manager")
	}()

	//////////////////////
	// Setup the cgroup
	//////////////////////
	cgInfo, err := createTestCgroup()
	require.NoError(t, err, "Failed to create test cgroup")
	defer cgInfo.Close()

	//////////////////////
	// Populate the policy map
	//////////////////////
	mockPolicyID := uint64(42)

	// populate policy values
	err = manager.GetPolicyValuesUpdateFunc()(mockPolicyID, []string{"/usr/bin/true"}, AddValuesToPolicy)
	require.NoError(t, err, "Failed to add policy values")

	// populate policy mode to monitor
	err = manager.GetPolicyModeUpdateFunc()(mockPolicyID, Monitor)
	require.NoError(t, err, "Failed to set policy mode")

	// populate cgroup to track
	err = manager.GetCgroupPolicyUpdateFunc()(mockPolicyID, []uint64{cgInfo.id}, AddPolicyToCgroups)
	require.NoError(t, err, "Failed to add policy to cgroup")

	//////////////////////
	// Try a binary that is allowed
	//////////////////////
	t.Log("Trying allowed binary in monitor mode")
	command := "/usr/bin/true"
	err = cgInfo.RunInCgroup(command, []string{})
	require.NoError(t, err, "Failed to run %s in cgroup", command)

	err = manager.findEventInChannel(monitoringChannel, cgInfo.id, command)
	require.Error(t, err, "Did not expect to find event for allowed binary")

	//////////////////////
	// Try a binary that is not allowed
	//////////////////////
	t.Log("Trying not allowed binary in monitor mode")
	command = "/usr/bin/who"
	err = cgInfo.RunInCgroup(command, []string{})
	require.NoError(t, err, "Failed to run %s in cgroup", command)

	err = manager.findEventInChannel(monitoringChannel, cgInfo.id, command)
	require.NoError(t, err, "Failed to find event for not allowed binary")

	//////////////////////
	// Switch to enforcing mode
	//////////////////////
	t.Log("Switching to enforcing mode")
	err = manager.GetPolicyModeUpdateFunc()(mockPolicyID, Protect)
	require.NoError(t, err, "Failed to set policy to protect")

	//////////////////////
	// Try a binary that is allowed
	//////////////////////
	// Should behave like the monitor mode
	t.Log("Trying allowed binary in enforcing mode")
	command = "/usr/bin/true"
	err = cgInfo.RunInCgroup(command, []string{})
	require.NoError(t, err, "Failed to run %s in cgroup", command)

	err = manager.findEventInChannel(monitoringChannel, cgInfo.id, command)
	require.Error(t, err, "Did not expect to find event for allowed binary")

	//////////////////////
	// Try a binary that is not allowed
	//////////////////////
	t.Log("Trying not allowed binary in enforcing mode")
	command = "/usr/bin/who"
	err = cgInfo.RunInCgroup(command, []string{})
	// should receive a permission denied error
	require.Error(t, err, "Failed to run %s in cgroup", command)

	// and we should find the event in the channel
	err = manager.findEventInChannel(monitoringChannel, cgInfo.id, command)
	require.NoError(t, err, "Failed to find event for allowed binary")
}
