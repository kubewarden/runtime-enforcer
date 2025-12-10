package bpf

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/neuvector/runtime-enforcer/internal/cgroups"
)

func (m *Manager) GetCgroupTrackerUpdateFunc() func(cgID uint64, cgroupPath string) error {
	return func(cgID uint64, cgroupPath string) error {
		return m.updateCgTrackerMap(cgID, cgroupPath)
	}
}

func (m *Manager) updateCgTrackerMap(cgID uint64, cgroupPath string) error {
	// todo!: to be sure the manager is not closing the ebpf objects, we should add a mutex around this function to avoid issues at cleanup time

	// we populate the entry for the cgroup id with itself as tracker id so that the child cgroups
	// can inherit the same tracker id
	if err := m.objs.CgtrackerMap.Update(&cgID, &cgID, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("failed to update cgroup tracker map for id %d: %w", cgID, err)
	}

	// We now walk the cgroup path to find all the child cgroups and map them to the same tracker id. This is useful is the container is already running and has already created child cgroups
	var walkErr error
	err := filepath.WalkDir(cgroupPath, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			if d == nil {
				return fmt.Errorf("cgrouptracker: failed to walk dir %s: %w", p, err)
			}
			return fs.SkipDir
		}
		if !d.IsDir() {
			return nil
		}

		if p == cgroupPath {
			return nil
		}

		trackedID, err := cgroups.GetCgroupIDFromPath(p)
		if err != nil {
			walkErr = errors.Join(walkErr, fmt.Errorf("failed to read id from '%s': %w", p, err))
			return nil
		}

		// the key here is the child cgroup id we just found
		merr := m.objs.CgtrackerMap.Update(&trackedID, &cgID, ebpf.UpdateAny)
		if merr != nil {
			walkErr = errors.Join(walkErr, fmt.Errorf("failed to update id (%d) for '%s': %w", trackedID, p, merr))
		}

		m.logger.Debug("added mapping",
			"tracked", trackedID,
			"tracker", cgID,
			"tracked path", p,
			"tracker path", cgroupPath)

		return nil
	})
	if err != nil {
		m.logger.Warn("failed to run walkdir", "error", err)
	}

	// we just log the error here, as the main update operation could be successful even if some child cgroups failed
	if walkErr != nil {
		m.logger.Warn("failed to retrieve some the cgroup id for some paths", "cgtracker", true, "error", walkErr)
	}
	return nil
}

func (m *Manager) cgroupTrackerStart(ctx context.Context) error {
	var cgroupMkdir link.Link
	var cgroupRelease link.Link
	defer func() {
		m.logger.InfoContext(ctx, "BPF Cgroup Tracker stopped")
		if cgroupMkdir != nil {
			if err := cgroupMkdir.Close(); err != nil {
				m.logger.ErrorContext(ctx, "failed to close cgroup mkdir link", "error", err)
			}
		}
		if cgroupRelease != nil {
			if err := cgroupRelease.Close(); err != nil {
				m.logger.ErrorContext(ctx, "failed to close cgroup release link", "error", err)
			}
		}
	}()

	var err error
	// We attach the cgroup tracker programs
	cgroupMkdir, err = link.AttachTracing(link.TracingOptions{
		Program: m.objs.TgCgtrackerCgroupMkdir,
	})
	if err != nil {
		return fmt.Errorf("failed to attach cgroup mkdir tracing prog: %w", err)
	}

	cgroupRelease, err = link.AttachTracing(link.TracingOptions{
		Program: m.objs.TgCgtrackerCgroupRelease,
	})
	if err != nil {
		return fmt.Errorf("failed to attach cgroup release tracing prog: %w", err)
	}

	// Wait until context is done
	<-ctx.Done()
	return nil
}
