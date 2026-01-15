// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon
// Copyright 2025 Authors of Runtime-enforcer

package cgroups

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"

	"go.uber.org/multierr"
	"golang.org/x/sys/unix"
)

const (
	// CgroupUnsetValue is a generic unset value that means unset group magic.
	// Returned in case of errors. Values could be:
	//   - CgroupUnsetValue: unset
	//   - unix.CGROUP_SUPER_MAGIC: cgroupv1
	//   - unix.CGROUP2_SUPER_MAGIC: cgroupv2
	CgroupUnsetValue = 0

	// CgroupSubsysCount is the max cgroup subsystems count we find in x86 vmlinux kernels.
	// See `enum cgroup_subsys_id` and value `CGROUP_SUBSYS_COUNT`.
	CgroupSubsysCount = 15

	// defaultProcFSPath is the default path to the proc filesystem.
	// todo!: make this configurable.
	defaultProcFSPath = "/proc"
)

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

type CgroupInfo struct {
	cgroupRoot  string
	fsMagic     uint64
	subsysV1Idx uint32
}

func (c *CgroupInfo) CgroupFsMagic() uint64 {
	return c.fsMagic
}

func (c *CgroupInfo) CgroupV1SubsysIdx() uint32 {
	return c.subsysV1Idx
}

func CgroupFsMagicString(fsMagic uint64) string {
	switch fsMagic {
	case unix.CGROUP_SUPER_MAGIC:
		return "cgroupv1"
	case unix.CGROUP2_SUPER_MAGIC:
		return "cgroupv2"
	default:
		panic("unknown cgroup fs magic")
	}
}

// checkInterestingController returns true if the controller name matches one of the target controllers.
func checkInterestingController(name string) bool {
	// They are usually the ones that are set up by systemd or other init
	// programs. We will use one of them in ebpf to get cgroup information.
	for _, controllerName := range []string{
		"memory",
		"pids",
		"cpuset",
	} {
		if name == controllerName {
			return true
		}
	}
	return false
}

// parseCgroupv1SubSysIDs() parse cgroupv1 controllers and save their css indexes.
// If the 'memory', 'pids' or 'cpuset' are not detected we fail, as we use them
// from BPF side to gather cgroup information and we need them to be
// exported by the kernel since their corresponding index allows us to
// fetch the cgroup from the corresponding cgroup subsystem state.
func parseCgroupv1SubSysIDs(logger *slog.Logger, filePath string) (uint32, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return 0, err
	}
	defer file.Close()

	fscanner := bufio.NewScanner(file)
	// Expected format:
	// #subsys_name    hierarchy   num_cgroups   enabled
	// memory          6           42            1
	// cpuset          2           5             1
	// pids            9           17            0

	fscanner.Scan() // ignore first entry
	var idx uint32
	// we save the controller names in case of controller not found
	var allcontrollersNames []string

	for fscanner.Scan() {
		line := fscanner.Text()
		fields := strings.Fields(line)
		if len(fields) != 0 {
			allcontrollersNames = append(allcontrollersNames, fields[0])
			if checkInterestingController(fields[0]) {
				// this is the active controller we are looking for
				return idx, nil
			}
		} else {
			// We expect at least two fields for each controller line
			logger.Warn("Cgroupv1 controller line has less than two fields", "line", line)
		}
		idx++
		// in ebpf we don't go beyond CgroupSubsysCount so it is useless to parse more
		if idx >= CgroupSubsysCount {
			break
		}
	}
	return 0, fmt.Errorf("looped until index %v, no active controllers among: %v", idx, allcontrollersNames)
}

// Check and log Cgroupv2 active controllers.
func checkCgroupv2Controllers(cgroupPath string) (string, error) {
	file := filepath.Join(cgroupPath, "cgroup.controllers")
	data, err := os.ReadFile(file)
	if err != nil {
		return "", fmt.Errorf("failed to read %s: %w", file, err)
	}

	activeControllers := strings.TrimRight(string(data), "\n")
	if len(activeControllers) == 0 {
		return "", fmt.Errorf("no active controllers from '%s'", file)
	}
	return activeControllers, nil
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
	case unix.CGROUP2_SUPER_MAGIC, unix.CGROUP_SUPER_MAGIC, unix.TMPFS_MAGIC:
		return nil
	default:
		return fmt.Errorf("cannot determine cgroup root: path '%s' is not a cgroup fs", path)
	}
}

func detectCgroupFSMagic(cgroupRoot string) (uint64, error) {
	var st syscall.Statfs_t

	if err := syscall.Statfs(cgroupRoot, &st); err != nil {
		return CgroupUnsetValue, err
	}

	switch st.Type {
	case unix.CGROUP2_SUPER_MAGIC:
		return unix.CGROUP2_SUPER_MAGIC, nil
	case unix.TMPFS_MAGIC:
		err := syscall.Statfs(filepath.Join(cgroupRoot, "unified"), &st)
		if err == nil && st.Type == unix.CGROUP2_SUPER_MAGIC {
			// Hybrid mode
			return unix.CGROUP_SUPER_MAGIC, nil
		}
		// Legacy mode
		return unix.CGROUP_SUPER_MAGIC, nil
	default:
		return CgroupUnsetValue, fmt.Errorf("wrong type '%d' for cgroupfs '%s'", st.Type, cgroupRoot)
	}
}

var (
	cgroupRootCheckOnce sync.Once //nolint:gochecknoglobals // we want it global for a global function.
	cgroupRootPath      string    //nolint:gochecknoglobals // we want it global for a global function.
	errCgroupRootPath   error
)

// GetHostCgroupRoot tries to retrieve the host cgroup root
//
// for now we are checking /sys/fs/cgroup under host /proc's init.
// For systems where the cgroup is mounted in a non-standard location, we could
// also check host's /proc/mounts.
func GetHostCgroupRoot() (string, error) {
	cgroupRootCheckOnce.Do(func() {
		cgroupRootPath, errCgroupRootPath = getHostCgroupRoot()
	})
	return cgroupRootPath, errCgroupRootPath
}

func getHostCgroupRoot() (string, error) {
	var multiErr error

	// We first try /proc/1/root/sys/fs/cgroup/
	path1 := filepath.Join(defaultProcFSPath, "1/root/sys/fs/cgroup")
	err := tryHostCgroup(path1)
	if err == nil {
		return path1, nil
	}
	multiErr = multierr.Append(multiErr, fmt.Errorf("failed to set path %s as cgroup root: %w", path1, err))

	// We now try some known controller name /proc/1/root/sys/fs/cgroup/<controller>
	for _, ctrl := range []string{
		"memory",
		"pids",
		"cpuset",
	} {
		path := filepath.Join(path1, ctrl)
		err = tryHostCgroup(path)
		if err == nil {
			return path, nil
		}
		multiErr = multierr.Append(multiErr, fmt.Errorf("failed to set path %s as cgroup root: %w", path, err))
	}

	// todo!: we can probably get a custom cgroup root from the user through env variable.
	return "", multiErr
}

// GetCgroupInfo retrieves cgroup information such as cgroup root, fs magic and subsys index.
func GetCgroupInfo(logger *slog.Logger) (*CgroupInfo, error) {
	// We first need to find the host cgroup root. We still don't know if it is v1 or v2.
	cgroupRoot, err := GetHostCgroupRoot()
	if err != nil {
		return nil, fmt.Errorf("cannot get host cgroup root: %w", err)
	}

	// Understand cgroupfs magic
	cgroupFsMagic, err := detectCgroupFSMagic(cgroupRoot)
	if err != nil {
		return nil, fmt.Errorf("cannot get cgroupfs magic: %w", err)
	}

	var subsysV1Idx uint32
	switch cgroupFsMagic {
	case unix.CGROUP_SUPER_MAGIC:
		// If we use Cgroupv1, we need the subsys idx for ebpf.
		subsysV1Idx, err = parseCgroupv1SubSysIDs(logger, filepath.Join(defaultProcFSPath, "cgroups"))
		if err != nil {
			return nil, fmt.Errorf("failed to parse cgroupv1 subsys ids: %w", err)
		}
	case unix.CGROUP2_SUPER_MAGIC:
		// If we use Cgroupv2, we just want to log the active controllers.
		path := filepath.Clean(fmt.Sprintf("%s/1/root/%s", defaultProcFSPath, cgroupRoot))
		var controllers string
		controllers, err = checkCgroupv2Controllers(path)
		if err != nil {
			return nil, fmt.Errorf("failed to check cgroupv2 controllers: %w", err)
		}
		logger.Info("Cgroupv2 supported controllers detected successfully",
			"cgroup.controllers", strings.Fields(controllers))
	default:
		panic("unknown cgroup filesystem magic")
	}

	return &CgroupInfo{
		cgroupRoot:  cgroupRoot,
		fsMagic:     cgroupFsMagic,
		subsysV1Idx: subsysV1Idx,
	}, nil
}
