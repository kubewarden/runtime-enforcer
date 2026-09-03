package bpf

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/kubewarden/runtime-enforcer/internal/cgroups"
)

func (m *Manager) GetCgroupTrackerUpdateFunc() func(cgID uint64, cgroupPath string) error {
	return func(cgID uint64, cgroupPath string) error {
		return m.handleErrOnShutdown(UpdateCgTrackerMap(m.logger, m.objs.CgtrackerMap, cgID, cgroupPath))
	}
}

func UpdateCgTrackerMap(logger *slog.Logger, cgTrackerMap *ebpf.Map, cgID uint64, cgroupPath string) error {
	// we populate the entry for the cgroup id with itself as tracker id so that the child cgroups
	// can inherit the same tracker id
	if err := cgTrackerMap.Update(&cgID, &cgID, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("failed to update cgroup tracker map for id %d: %w", cgID, err)
	}

	// If the container is not yet started it is impossible to have nested cgroups.
	// In this case, we provide an empty cgroup path since we don't need to walk it.
	if cgroupPath == "" {
		return nil
	}

	// We now walk the cgroup path to find all the child cgroups and map them to the same tracker id.
	// This is useful if the container is already running and has already created child cgroups.
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
		merr := cgTrackerMap.Update(&trackedID, &cgID, ebpf.UpdateAny)
		if merr != nil {
			walkErr = errors.Join(walkErr, fmt.Errorf("failed to update id (%d) for '%s': %w", trackedID, p, merr))
		}

		logger.Info("added nested cgroup",
			"nested ID", trackedID,
			"parent ID", cgID,
			"nested path", p,
			"parent path", cgroupPath)

		return nil
	})
	if err != nil {
		logger.Warn("failed to run walkdir", "error", err)
	}

	// we just log the error here, as the main update operation could be successful even if some child cgroups failed
	if walkErr != nil {
		logger.Warn("failed to retrieve some of the cgroup ids for some paths", "cgtracker", true, "error", walkErr)
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
