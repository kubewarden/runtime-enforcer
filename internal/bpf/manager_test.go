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
	"github.com/neuvector/runtime-enforcer/internal/types/policymode"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"
)

const (
	// in CI when running inside a little VM things can be slow, we previously used 1 second here but it was not enough.
	defaultEventTimeout = 10 * time.Second
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
		case <-time.After(defaultEventTimeout):
			return errors.New("timeout waiting for event")
		}
	}
}

func startManager(t *testing.T) (*Manager, func()) {
	// We always enable learning in tests for now so that we can wait for the first event to come
	// and understand that BPF programs are loaded and running
	enableLearning := true
	// Don't pin maps in tests - empty string disables pinning
	manager, err := NewManager(newTestLogger(t), enableLearning, ebpf.LogLevelBranch, "")
	require.NoError(t, err, "Failed to create BPF manager")
	require.NotNil(t, manager, "BPF manager is nil")

	ctx, cancel := context.WithCancel(t.Context())
	g, ctx := errgroup.WithContext(ctx)
	g.Go(func() error {
		return manager.Start(ctx)
	})

	cleanup := func() {
		cancel()
		require.NoError(t, g.Wait(), "Failed to stop BPF manager")
	}
	return manager, cleanup
}

func waitFirstEvent(m *Manager) error {
	for {
		select {
		case <-time.After(defaultEventTimeout):
			return errors.New("timeout waiting for first event")
		case <-m.GetLearningChannel():
			return nil
		}
	}
}

func checkManagerIsStarted(t *testing.T, m *Manager) error {
	ctx, cancel := context.WithCancel(t.Context())
	g, ctx := errgroup.WithContext(ctx)

	// we have a goroutine that keeps running a command in a loop
	g.Go(func() error {
		for {
			select {
			// Here we never return an error in case of context done,
			// because it is the unique way to stop this goroutine
			case <-ctx.Done():
				return nil
			case <-time.After(200 * time.Millisecond):
				if err := exec.Command("/usr/bin/true").Run(); err != nil {
					return err
				}
			}
		}
	})

	var multiErr error
	// we wait for the first event to come
	if err := waitFirstEvent(m); err != nil {
		multiErr = errors.Join(multiErr, err)
	}
	cancel()
	if err := g.Wait(); err != nil {
		multiErr = errors.Join(multiErr, err)
	}
	return multiErr
}

func waitRunningManager(t *testing.T) (*Manager, func()) {
	manager, cleanup := startManager(t)
	if err := checkManagerIsStarted(t, manager); err != nil {
		cleanup()
		t.Fatal(err)
	}
	return manager, cleanup
}

// run it with: go test -v -run TestNoVerifierFailures ./internal/bpf -count=1 -exec "sudo -E".
func TestNoVerifierFailures(t *testing.T) {
	enableLearning := true
	// Loading happens here so we can catch verifier errors without running the manager
	// Don't pin maps in tests - empty string disables pinning
	_, err := NewManager(newTestLogger(t), enableLearning, ebpf.LogLevelBranch, "")
	if err == nil {
		t.Log("BPF manager started successfully :)!!")
		return
	}
	var verr *ebpf.VerifierError
	if errors.As(err, &verr) {
		t.Log("Verifier errors detected:")
		for _, log := range verr.Log {
			t.Log(log)
		}
	}
	t.Log(err)
	t.FailNow()
}

func TestLearning(t *testing.T) {
	//////////////////////
	// Start BPF manager
	//////////////////////
	manager, cleanup := waitRunningManager(t)
	defer cleanup()

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

func TestMonitorProtectMode(t *testing.T) {
	manager, cleanup := waitRunningManager(t)
	defer cleanup()

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
	err = manager.GetPolicyModeUpdateFunc()(mockPolicyID, policymode.Monitor, UpdateMode)
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
	err = manager.GetPolicyModeUpdateFunc()(mockPolicyID, policymode.Protect, UpdateMode)
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

func TestMultiplePolicies(t *testing.T) {
	manager, cleanup := waitRunningManager(t)
	defer cleanup()

	mockPolicyID1 := uint64(42)
	err := manager.GetPolicyValuesUpdateFunc()(mockPolicyID1, []string{"/usr/bin/true"}, AddValuesToPolicy)
	require.NoError(t, err, "Failed to add policy 1 values")

	// Check if max entries for string maps is really greater than 1
	mockPolicyID2 := uint64(43)
	err = manager.GetPolicyValuesUpdateFunc()(mockPolicyID2, []string{"/usr/bin/who"}, AddValuesToPolicy)
	require.NoError(t, err, "Failed to add policy 2 values")
}
