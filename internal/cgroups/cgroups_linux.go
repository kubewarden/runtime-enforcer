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
	Id     uint32 // Hierarchy unique ID
	Idx    uint32 // Cgroup SubSys index
	Name   string // Controller name
	Active bool   // Will be set to true if controller is set and active
}

var (
	// Path where default cgroupfs is mounted.
	defaultCgroupRoot = "/sys/fs/cgroup"

	// todo!: we should allow to configure this.
	defaultProcFS = "/proc"

	/* Cgroup controllers that we are interested in
	 * are usually the ones that are setup by systemd
	 * or other init programs.
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
		CGROUP_UNDEF:   "undefined",
		CGROUP_LEGACY:  "Legacy mode (Cgroupv1)",
		CGROUP_HYBRID:  "Hybrid mode (Cgroupv1 and Cgroupv2)",
		CGROUP_UNIFIED: "Unified mode (Cgroupv2)",
	}[code]
}

// DetectCgroupFSMagic() runs by default DetectCgroupMode()
// CgroupFsMagicStr() Returns "Cgroupv2" or "Cgroupv1" based on passed magic.
func CgroupFsMagicStr(magic uint64) string {
	switch magic {
	case unix.CGROUP2_SUPER_MAGIC:
		return "Cgroupv2"
	case unix.CGROUP_SUPER_MAGIC:
		return "Cgroupv1"
	}

	return ""
}

func GetCgroupFSMagic() uint64 {
	return cgroupFSMagic
}

type FileHandle struct {
	Id uint64
}

func GetCgroupIdFromPath(cgroupPath string) (uint64, error) {
	var fh FileHandle

	handle, _, err := unix.NameToHandleAt(unix.AT_FDCWD, cgroupPath, 0)
	if err != nil {
		return 0, fmt.Errorf("nameToHandle on %s failed: %w", cgroupPath, err)
	}

	err = binary.Read(bytes.NewBuffer(handle.Bytes()), binary.LittleEndian, &fh)
	if err != nil {
		return 0, fmt.Errorf("decoding NameToHandleAt data failed: %w", err)
	}

	return fh.Id, nil
}

// parseCgroupv1SubSysIds() parse cgroupv1 controllers and save their
// hierarchy IDs and related css indexes.
// If the 'memory' or 'cpuset' are not detected we fail, as we use them
// from BPF side to gather cgroup information and we need them to be
// exported by the kernel since their corresponding index allows us to
// fetch the cgroup from the corresponding cgroup subsystem state.
func parseCgroupv1SubSysIds(filePath string) error {
	var allcontrollers []string

	file, err := os.Open(filePath)
	if err != nil {
		return err
	}

	defer file.Close()

	fscanner := bufio.NewScanner(file)
	idx := 0
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
				if idx >= CGROUP_SUBSYS_COUNT {
					/* Maybe some cgroups are not upstream? */
					return fmt.Errorf(
						"Cgroupv1 default subsystem '%s' is indexed at idx=%d higher than CGROUP_SUBSYS_COUNT=%d",
						fields[0],
						idx,
						CGROUP_SUBSYS_COUNT,
					)
				}

				id, err := strconv.ParseUint(fields[1], 10, 32)
				if err == nil {
					CgroupControllers[i].Id = uint32(id)
					CgroupControllers[i].Idx = uint32(idx)
					CgroupControllers[i].Active = true
				} else {
					slog.Warn(fmt.Sprintf("Cgroupv1 parsing controller line from '%s' failed", filePath),
						"error", err,
						"cgroup.fs", cgroupFSPath,
						"cgroup.controller.name", controller.Name)
				}
			}
		}
		idx++
	}

	slog.Debug("Cgroupv1 available controllers",
		"cgroup.fs", cgroupFSPath,
		"cgroup.controllers", fmt.Sprintf("[%s]", strings.Join(allcontrollers, " ")))

	for _, controller := range CgroupControllers {
		// Print again everything that is available and if not, fail with error
		if controller.Active {
			slog.Info(fmt.Sprintf("Cgroupv1 supported controller '%s' is active on the system", controller.Name),
				"cgroup.fs", cgroupFSPath,
				"cgroup.controller.name", controller.Name,
				"cgroup.controller.hierarchyID", controller.Id,
				"cgroup.controller.index", controller.Idx)
		} else {
			var err error
			// Warn with error
			switch controller.Name {
			case "memory":
				err = errors.New("Cgroupv1 controller 'memory' is not active, ensure kernel CONFIG_MEMCG=y and CONFIG_MEMCG_V1=y are set")
			case "cpuset":
				err = errors.New("Cgroupv1 controller 'cpuset' is not active, ensure kernel CONFIG_CPUSETS=y and CONFIG_CPUSETS_V1=y are set")
			default:
				slog.Warn(fmt.Sprintf("Cgroupv1 '%s' supported controller is missing", controller.Name), "cgroup.fs", cgroupFSPath)
			}

			if err != nil {
				slog.Warn(fmt.Sprintf("Cgroupv1 '%s' supported controller is missing", controller.Name),
					"error", err, "cgroup.fs", cgroupFSPath)
				return err
			}
		}
	}

	return nil
}

// DiscoverSubSysIds() Discover Cgroup SubSys IDs and indexes.
// of the corresponding controllers that we are interested
// in. We need this dynamic behavior since these controllers are
// compile config.
func DiscoverSubSysIds() error {
	var err error
	magic := GetCgroupFSMagic()
	if magic == CGROUP_UNSET_VALUE {
		magic, err = DetectCgroupFSMagic()
		if err != nil {
			return err
		}
	}

	switch magic {
	case unix.CGROUP_SUPER_MAGIC:
		return parseCgroupv1SubSysIds(filepath.Join(defaultProcFS, "cgroups"))
	case unix.CGROUP2_SUPER_MAGIC:
		/* Parse Root Cgroup active controllers.
		 * This step helps debugging since we may have some
		 * race conditions when processes are moved or spawned in their
		 * appropriate cgroups which affect cgroup association, so
		 * having more information on the environment helps to debug
		 * or reproduce.
		 */
		path := filepath.Clean(fmt.Sprintf("%s/1/root/%s", defaultProcFS, cgroupFSPath))
		return checkCgroupv2Controllers(path)
	}

	return errors.New("could not detect Cgroup filesystem")
}

// GetCgrpSubsystemIdx() returns the Index of the subsys
// or hierarchy to be used to track processes.
func GetCgrpv1SubsystemIdx() uint32 {
	return cgrpv1SubsystemIdx
}

// GetCgrpControllerName() returns the name of the controller that is
// being used as fallback from the css to get cgroup information and
// track processes.
func GetCgrpControllerName() string {
	for _, controller := range CgroupControllers {
		if controller.Active && controller.Idx == cgrpv1SubsystemIdx {
			return controller.Name
		}
	}
	return ""
}

// Check and log Cgroupv2 active controllers.
func checkCgroupv2Controllers(cgroupPath string) error {
	file := filepath.Join(cgroupPath, "cgroup.controllers")
	data, err := os.ReadFile(file)
	if err != nil {
		return fmt.Errorf("failed to read %s: %w", file, err)
	}

	activeControllers := strings.TrimRight(string(data), "\n")
	if len(activeControllers) == 0 {
		return fmt.Errorf("no active controllers from '%s'", file)
	}

	slog.Info("Cgroupv2 supported controllers detected successfully",
		"cgroup.fs", cgroupFSPath,
		"cgroup.path", cgroupPath,
		"cgroup.controllers", strings.Fields(activeControllers),
		"cgroup.hierarchyID", CGROUP_DEFAULT_HIERARCHY)

	return nil
}

func detectCgroupMode(cgroupfs string) (CgroupModeCode, error) {
	var st syscall.Statfs_t

	if err := syscall.Statfs(cgroupfs, &st); err != nil {
		return CGROUP_UNDEF, err
	}

	switch st.Type {
	case unix.CGROUP2_SUPER_MAGIC:
		return CGROUP_UNIFIED, nil
	case unix.TMPFS_MAGIC:
		err := syscall.Statfs(filepath.Join(cgroupfs, "unified"), &st)
		if err == nil && st.Type == unix.CGROUP2_SUPER_MAGIC {
			return CGROUP_HYBRID, nil
		}
		return CGROUP_LEGACY, nil
	}

	return CGROUP_UNDEF, fmt.Errorf("wrong type '%d' for cgroupfs '%s'", st.Type, cgroupfs)
}

// DetectCgroupMode() Returns the current Cgroup mode that is applied to the system
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
		if cgroupMode != CGROUP_UNDEF {
			slog.Info("Cgroup mode detection succeeded",
				"cgroup.fs", cgroupFSPath,
				"cgroup.mode", cgroupMode.String())
		}
	})

	if cgroupMode == CGROUP_UNDEF {
		return CGROUP_UNDEF, errors.New("could not detect Cgroup Mode")
	}

	return cgroupMode, nil
}

// DetectCgroupFSMagic() runs by default DetectCgroupMode()
// Return the Cgroupfs v1 or v2 that will be used by bpf programs.
func DetectCgroupFSMagic() (uint64, error) {
	// Run get cgroup mode again in case
	mode, err := DetectCgroupMode()
	if err != nil {
		return CGROUP_UNSET_VALUE, err
	}

	// Run this once and log output
	detectCgroupFSOnce.Do(func() {
		switch mode {
		case CGROUP_LEGACY, CGROUP_HYBRID:
			/* In both legacy or Hybrid modes we switch to Cgroupv1 from bpf side. */
			slog.Debug("Cgroup BPF helpers will run in raw Cgroup mode", "cgroup.fs", cgroupFSPath)
			cgroupFSMagic = unix.CGROUP_SUPER_MAGIC
		case CGROUP_UNIFIED:
			slog.Debug(
				"Cgroup BPF helpers will run in Cgroupv2 mode or fallback to raw Cgroup on errors",
				"cgroup.fs",
				cgroupFSPath,
			)
			cgroupFSMagic = unix.CGROUP2_SUPER_MAGIC
		}
	})

	if cgroupFSMagic == CGROUP_UNSET_VALUE {
		return CGROUP_UNSET_VALUE, errors.New("could not detect Cgroup filesystem Magic")
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
