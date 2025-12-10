package cgroups

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"go.uber.org/multierr"
	"golang.org/x/sys/unix"
)

type CgroupController struct {
	ID     uint32 // Hierarchy unique ID
	Idx    uint32 // Cgroup SubSys index
	Name   string // Controller name
	Active bool   // Will be set to true if controller is set and active
}

var (
	// defaultCgroupRoot is the path where cgroupfs is mounted.
	defaultCgroupRoot = "/sys/fs/cgroup"

	// defaultProcFS is the root path for procfs.
	// todo!: we should allow to configure this.
	defaultProcFS = "/proc"

	/* CgroupControllers lists the cgroup controllers that we are interested in.
	 * They are usually the ones that are set up by systemd or other init
	 * programs.
	 */
	CgroupControllers = []CgroupController{
		{Name: "memory"}, // Memory first
		{Name: "pids"},   // pids second
		{Name: "cpuset"}, // fallback
	}

	detectCgrpModeOnce sync.Once
	cgroupMode         CgroupModeCode

	detectCgroupFSOnce sync.Once
	cgroupFSPath       string
	cgroupFSMagic      uint64

	cgrpv1SubsystemIdx uint32 // Not set in case of cgroupv2
)

func (code CgroupModeCode) String() string {
	return [...]string{
		CgroupUndef:   "undefined",
		CgroupLegacy:  "Legacy mode (Cgroupv1)",
		CgroupHybrid:  "Hybrid mode (Cgroupv1 and Cgroupv2)",
		CgroupUnified: "Unified mode (Cgroupv2)",
	}[code]
}

// CgroupFsMagicStr returns "Cgroupv2" or "Cgroupv1" based on passed magic.
// DetectCgroupFSMagic runs DetectCgroupMode by default.
func CgroupFsMagicStr(magic uint64) string {
	switch magic {
	case unix.CGROUP2_SUPER_MAGIC:
		return "Cgroupv2"
	case unix.CGROUP_SUPER_MAGIC:
		return "Cgroupv1"
	}

	return ""
}

// GetCgroupFSMagic returns the cached cgroup filesystem magic.
func GetCgroupFSMagic() uint64 {
	return cgroupFSMagic
}

type FileHandle struct {
	ID uint64
}

// GetCgroupIDFromPath returns the cgroup ID from the given path.
func GetCgroupIDFromPath(cgroupPath string) (uint64, error) {
	var fh FileHandle

	handle, _, err := unix.NameToHandleAt(unix.AT_FDCWD, cgroupPath, 0)
	if err != nil {
		return 0, fmt.Errorf("nameToHandle on %s failed: %w", cgroupPath, err)
	}

	err = binary.Read(bytes.NewBuffer(handle.Bytes()), binary.LittleEndian, &fh)
	if err != nil {
		return 0, fmt.Errorf("decoding NameToHandleAt data failed: %w", err)
	}

	return fh.ID, nil
}

// parseCgroupv1SubSysIds() parse cgroupv1 controllers and save their
// hierarchy IDs and related css indexes.
// If the 'memory' or 'cpuset' are not detected we fail, as we use them
// from BPF side to gather cgroup information and we need them to be
// exported by the kernel since their corresponding index allows us to
// fetch the cgroup from the corresponding cgroup subsystem state.
func parseCgroupv1SubSysIds(logger *slog.Logger, filePath string) error {
	var allcontrollers []string

	file, err := os.Open(filePath)
	if err != nil {
		return err
	}

	defer file.Close()

	fscanner := bufio.NewScanner(file)
	var idx uint32
	fscanner.Scan() // ignore first entry
	for fscanner.Scan() {
		line := fscanner.Text()
		fields := strings.Fields(line)

		allcontrollers = append(allcontrollers, fields[0])

		// No need to read enabled field as it can be enabled on
		// root without having a proper cgroup name to reflect that
		// or the controller is not active on the unified cgroupv2.
		for i, controller := range CgroupControllers {
			if fields[0] == controller.Name {
				/* We care only for the controllers that we want */
				if idx >= CgroupSubsysCount {
					/* Maybe some cgroups are not upstream? */
					return fmt.Errorf(
						"Cgroupv1 default subsystem '%s' is indexed at idx=%d higher than CgroupSubsysCount=%d",
						fields[0],
						idx,
						CgroupSubsysCount,
					)
				}

				var id uint64
				id, err = strconv.ParseUint(fields[1], 10, 32)
				if err == nil {
					CgroupControllers[i].ID = uint32(id)
					CgroupControllers[i].Idx = idx
					CgroupControllers[i].Active = true
				} else {
					logger.Warn(fmt.Sprintf("Cgroupv1 parsing controller line from '%s' failed", filePath),
						"error", err,
						"cgroup.fs", cgroupFSPath,
						"cgroup.controller.name", controller.Name)
				}
			}
		}
		idx++
	}

	logger.Debug("Cgroupv1 available controllers",
		"cgroup.fs", cgroupFSPath,
		"cgroup.controllers", fmt.Sprintf("[%s]", strings.Join(allcontrollers, " ")))

	for _, controller := range CgroupControllers {
		// Print again everything that is available and if not, fail with error
		if controller.Active {
			logger.Info(fmt.Sprintf("Cgroupv1 supported controller '%s' is active on the system", controller.Name),
				"cgroup.fs", cgroupFSPath,
				"cgroup.controller.name", controller.Name,
				"cgroup.controller.hierarchyID", controller.ID,
				"cgroup.controller.index", controller.Idx)
		} else {
			// Warn with error
			switch controller.Name {
			case "memory":
				err = errors.New("Cgroupv1 controller 'memory' is not active, ensure kernel CONFIG_MEMCG=y and CONFIG_MEMCG_V1=y are set")
			case "cpuset":
				err = errors.New("Cgroupv1 controller 'cpuset' is not active, ensure kernel CONFIG_CPUSETS=y and CONFIG_CPUSETS_V1=y are set")
			default:
				logger.Warn(fmt.Sprintf("Cgroupv1 '%s' supported controller is missing", controller.Name), "cgroup.fs", cgroupFSPath)
			}

			if err != nil {
				logger.Warn(fmt.Sprintf("Cgroupv1 '%s' supported controller is missing", controller.Name),
					"error", err, "cgroup.fs", cgroupFSPath)
				return err
			}
		}
	}

	return nil
}

// DiscoverSubSysIDs discovers Cgroup SubSys IDs and indexes of the controllers we are interested in.
// We need this dynamic behavior since these controllers are compile-time configuration.
func DiscoverSubSysIDs(logger *slog.Logger) error {
	var err error
	magic := GetCgroupFSMagic()
	if magic == CgroupUnsetValue {
		magic, err = DetectCgroupFSMagic(logger)
		if err != nil {
			return err
		}
	}

	switch magic {
	case unix.CGROUP_SUPER_MAGIC:
		return parseCgroupv1SubSysIds(logger, filepath.Join(defaultProcFS, "cgroups"))
	case unix.CGROUP2_SUPER_MAGIC:
		/* Parse Root Cgroup active controllers.
		 * This step helps debugging since we may have some
		 * race conditions when processes are moved or spawned in their
		 * appropriate cgroups which affect cgroup association, so
		 * having more information on the environment helps to debug
		 * or reproduce.
		 */
		path := filepath.Clean(fmt.Sprintf("%s/1/root/%s", defaultProcFS, cgroupFSPath))
		return checkCgroupv2Controllers(logger, path)
	}

	return errors.New("could not detect Cgroup filesystem")
}

// GetCgrpv1SubsystemIdx returns the Index of the subsys or hierarchy to be used to track processes.
func GetCgrpv1SubsystemIdx() uint32 {
	return cgrpv1SubsystemIdx
}

// GetCgrpControllerName returns the name of the controller that is being used as fallback
// from the css to get cgroup information and track processes.
func GetCgrpControllerName() string {
	for _, controller := range CgroupControllers {
		if controller.Active && controller.Idx == cgrpv1SubsystemIdx {
			return controller.Name
		}
	}
	return ""
}

// Check and log Cgroupv2 active controllers.
func checkCgroupv2Controllers(logger *slog.Logger, cgroupPath string) error {
	file := filepath.Join(cgroupPath, "cgroup.controllers")
	data, err := os.ReadFile(file)
	if err != nil {
		return fmt.Errorf("failed to read %s: %w", file, err)
	}

	activeControllers := strings.TrimRight(string(data), "\n")
	if len(activeControllers) == 0 {
		return fmt.Errorf("no active controllers from '%s'", file)
	}

	logger.Info("Cgroupv2 supported controllers detected successfully",
		"cgroup.fs", cgroupFSPath,
		"cgroup.path", cgroupPath,
		"cgroup.controllers", strings.Fields(activeControllers),
		"cgroup.hierarchyID", CgroupDefaultHierarchy)
	return nil
}

func detectCgroupMode(cgroupfs string) (CgroupModeCode, error) {
	var st syscall.Statfs_t

	if err := syscall.Statfs(cgroupfs, &st); err != nil {
		return CgroupUndef, err
	}

	switch st.Type {
	case unix.CGROUP2_SUPER_MAGIC:
		return CgroupUnified, nil
	case unix.TMPFS_MAGIC:
		err := syscall.Statfs(filepath.Join(cgroupfs, "unified"), &st)
		if err == nil && st.Type == unix.CGROUP2_SUPER_MAGIC {
			return CgroupHybrid, nil
		}
		return CgroupLegacy, nil
	}

	return CgroupUndef, fmt.Errorf("wrong type '%d' for cgroupfs '%s'", st.Type, cgroupfs)
}

// DetectCgroupMode returns the current Cgroup mode that is applied to the system.
// This applies to systemd and non-systemd machines, possible values:
//   - CGROUP_UNDEF: undefined
//   - CGROUP_LEGACY: Cgroupv1 legacy controllers
//   - CGROUP_HYBRID: Cgroupv1 and Cgroupv2 set up by systemd
//   - CGROUP_UNIFIED: Pure Cgroupv2 hierarchy
//
// Reference: https://systemd.io/CGROUP_DELEGATION/
func DetectCgroupMode() (CgroupModeCode, error) {
	detectCgrpModeOnce.Do(func() {
		var err error
		cgroupFSPath = defaultCgroupRoot
		cgroupMode, err = detectCgroupMode(cgroupFSPath)
		if err != nil {
			slog.Error("Could not detect Cgroup Mode", "cgroup.fs", cgroupFSPath, "error", err)
		}
		if cgroupMode != CgroupUndef {
			slog.Info("Cgroup mode detection succeeded",
				"cgroup.fs", cgroupFSPath,
				"cgroup.mode", cgroupMode.String())
		}
	})

	if cgroupMode == CgroupUndef {
		return CgroupUndef, errors.New("could not detect Cgroup Mode")
	}

	return cgroupMode, nil
}

// DetectCgroupFSMagic runs DetectCgroupMode and returns the cgroupfs v1 or v2 that will be used by BPF programs.
func DetectCgroupFSMagic(logger *slog.Logger) (uint64, error) {
	// Run get cgroup mode again in case
	mode, err := DetectCgroupMode()
	if err != nil {
		return CgroupUnsetValue, err
	}

	// Run this once and log output
	detectCgroupFSOnce.Do(func() {
		switch mode {
		case CgroupLegacy, CgroupHybrid:
			/* In both legacy or Hybrid modes we switch to Cgroupv1 from bpf side. */
			logger.Debug("Cgroup BPF helpers will run in raw Cgroup mode", "cgroup.fs", cgroupFSPath)
			cgroupFSMagic = unix.CGROUP_SUPER_MAGIC
		case CgroupUnified:
			logger.Debug(
				"Cgroup BPF helpers will run in Cgroupv2 mode or fallback to raw Cgroup on errors",
				"cgroup.fs",
				cgroupFSPath,
			)
			cgroupFSMagic = unix.CGROUP2_SUPER_MAGIC
		case CgroupUndef:
			cgroupFSMagic = CgroupUnsetValue
			logger.Error("Cgroup BPF helpers could not determine Cgroup mode", "cgroup.fs", cgroupFSPath)
		}
	})

	if cgroupFSMagic == CgroupUnsetValue {
		return CgroupUnsetValue, errors.New("could not detect Cgroup filesystem Magic")
	}

	return cgroupFSMagic, nil
}

func tryHostCgroup(path string) error {
	var st, pst unix.Stat_t
	if err := unix.Lstat(path, &st); err != nil {
		return fmt.Errorf("cannot determine cgroup root: error acessing path '%s': %w", path, err)
	}

	parent := filepath.Dir(path)
	if err := unix.Lstat(parent, &pst); err != nil {
		return fmt.Errorf("cannot determine cgroup root: error acessing parent path '%s': %w", parent, err)
	}

	if st.Dev == pst.Dev {
		return fmt.Errorf("cannot determine cgroup root: '%s' does not appear to be a mount point", path)
	}

	fst := unix.Statfs_t{}
	if err := unix.Statfs(path, &fst); err != nil {
		return fmt.Errorf("cannot determine cgroup root: failed to get info for '%s'", path)
	}

	switch fst.Type {
	case unix.CGROUP2_SUPER_MAGIC, unix.CGROUP_SUPER_MAGIC:
		return nil
	default:
		return fmt.Errorf("cannot determine cgroup root: path '%s' is not a cgroup fs", path)
	}
}

// HostCgroupRoot tries to retrieve the host cgroup root
//
// For cgroupv1, we return the directory of the contoller currently used.
//
// for now we are checking /sys/fs/cgroup under host /proc's init.
// For systems where the cgroup is mounted in a non-standard location, we could
// also check host's /proc/mounts.
func HostCgroupRoot() (string, error) {
	components := []string{
		defaultProcFS, "1", "root",
		"sys", "fs", "cgroup",
		GetCgrpControllerName(),
	}

	path1 := filepath.Join(components...)
	err1 := tryHostCgroup(path1)
	if err1 == nil {
		return path1, nil
	}

	path2 := filepath.Join(components[:len(components)-1]...)
	err2 := tryHostCgroup(path2)
	if err2 == nil {
		return path2, nil
	}

	err := multierr.Append(
		fmt.Errorf("failed to set path %s as cgroup root %w", path1, err1),
		fmt.Errorf("failed to set path %s as cgroup root %w", path2, err2),
	)
	return "", fmt.Errorf("failed to set cgroup root: %w", err)
}
