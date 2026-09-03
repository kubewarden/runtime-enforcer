package bpf

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"syscall"
	"testing"
	"time"

	"github.com/kubewarden/runtime-enforcer/internal/cgroups"
	"github.com/kubewarden/runtime-enforcer/internal/testutil"
	"github.com/kubewarden/runtime-enforcer/internal/types/policymode"
	"golang.org/x/sync/errgroup"
)

//////////////////////
// Channel helpers
//////////////////////

type ChannelType int

const (
	learningChannel ChannelType = iota
	monitoringChannel
)

func (c ChannelType) String() string {
	switch c {
	case learningChannel:
		return "learning"
	case monitoringChannel:
		return "monitoring"
	default:
		return "unknown"
	}
}

//////////////////////
// Cgroup runner
//////////////////////

type cgroupRunner struct {
	manager        *Manager
	managerCleanup func()
	cgInfo         cgroupInfo
}

func startManager(ctx context.Context, logger *slog.Logger) (*Manager, func(), error) {
	// We always enable learning in tests for now so that we can wait for the first event to come
	// and understand that BPF programs are loaded and running
	enableLearning := true
	manager, err := NewManager(logger, enableLearning)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create BPF manager: %w", err)
	}

	ctx, cancel := context.WithCancel(ctx)
	g, ctx := errgroup.WithContext(ctx)
	g.Go(func() error {
		return manager.Start(ctx)
	})

	return manager, func() {
		cancel()
		g.Wait()
	}, nil
}

func checkManagerIsStarted(m *Manager, cgInfo *cgroupInfo) error {
	timeoutChan := time.After(5 * time.Second)

	for {
		select {
		case <-m.GetLearningChannel():
			return nil
		case <-timeoutChan:
			return errors.New("timeout waiting for first event")
		case <-time.After(250 * time.Millisecond):
			// we continuously run a command to generate events
			if err := cgInfo.RunInCgroup("/usr/bin/true", []string{}); err != nil {
				return err
			}
		}
	}
}

func (m *Manager) findEventInChannel(ty ChannelType, cgID uint64, expectedPath string) error {
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
			if event.CgTrackerID == cgID &&
				event.ExePath == expectedPath {
				m.logger.Info("Found event", "event", event)
				return nil
			}
		// this timer is recreated on each loop iteration
		// so if we don't receive events for 1 second we time out
		case <-time.After(1 * time.Second):
			return errors.New("timeout waiting for event")
		}
	}
}

type runCommandArgs struct {
	command         string
	channel         ChannelType
	shouldEPERM     bool
	shouldFindEvent bool
	// use it when command is != from the path we want to find in the buffer.
	expectedPath string
}

func (r *cgroupRunner) runAndFindCommand(args *runCommandArgs) error {
	err := r.cgInfo.RunInCgroup(args.command, []string{})
	if args.shouldEPERM {
		if err == nil || !errors.Is(err, syscall.EPERM) {
			return fmt.Errorf("expected EPERM error, got: %w", err)
		}
	} else if err != nil {
		return fmt.Errorf("failed to run %s in cgroup: %w", args.command, err)
	}

	// usually the path is equal to the command but this is not always true
	// for example, when using memfd. if `expectedPath` is set, we use the command string
	// to run it and the expectedPath to assert inside the buffer.
	matchPath := args.command
	if args.expectedPath != "" {
		matchPath = args.expectedPath
	}

	// Get the event
	err = r.manager.findEventInChannel(args.channel, r.cgInfo.id, matchPath)
	if args.shouldFindEvent {
		if err != nil {
			return fmt.Errorf(
				"failed to find (command: %s, cgroup: %d) in channel %s: %w",
				args.command,
				r.cgInfo.id,
				args.channel,
				err,
			)
		}
	} else if err == nil {
		return fmt.Errorf("Did not expect to find (command: %s, cgroup: %d)", args.command, r.cgInfo.id)
	}
	return nil
}

func (r *cgroupRunner) populatePolicyForRunnerCgroup(policyID uint64, mode policymode.Mode, binaries []string) error {
	err := r.manager.GetPolicyUpdateBinariesFunc()(
		policyID,
		binaries,
		AddValuesToPolicy,
	)
	if err != nil {
		return fmt.Errorf("Failed to add policy values: %w", err)
	}

	err = r.manager.GetPolicyModeUpdateFunc()(policyID, mode, UpdateMode)
	if err != nil {
		return fmt.Errorf("Failed to set policy mode: %w", err)
	}

	err = r.manager.GetCgroupPolicyUpdateFunc()(
		policyID, []uint64{r.cgInfo.id}, AddPolicyToCgroups,
	)
	if err != nil {
		return fmt.Errorf("Failed to add policy to cgroup: %w", err)
	}
	return nil
}

func (r *cgroupRunner) close() {
	r.cgInfo.Close()
	r.managerCleanup()
}

func newCgroupRunnerWithLogger(t *testing.T, logger *slog.Logger) (*cgroupRunner, error) {
	// Start the manager and wait for it to be ready
	manager, cleanup, err := startManager(t.Context(), logger)
	if err != nil {
		return nil, err
	}

	defer func() {
		if err != nil {
			cleanup()
		}
	}()

	// Create the cgroup where we will run our commands
	// the manager is already started so we can use `GetCgroupResolutionPrefix`
	cgInfo, err := createTestCgroup(cgroups.GetCgroupResolutionPrefix())
	if err != nil {
		return nil, err
	}

	// track the cgroup
	err = manager.GetCgroupTrackerUpdateFunc()(cgInfo.id, "")
	if err != nil {
		return nil, err
	}

	if err = checkManagerIsStarted(manager, &cgInfo); err != nil {
		return nil, err
	}

	return &cgroupRunner{
		manager:        manager,
		managerCleanup: cleanup,
		cgInfo:         cgInfo,
	}, nil
}

func newCgroupRunner(t *testing.T) (*cgroupRunner, error) {
	return newCgroupRunnerWithLogger(t, testutil.NewTestLogger(t))
}
