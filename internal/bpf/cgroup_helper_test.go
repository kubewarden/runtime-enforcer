package bpf

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"

	"github.com/kubewarden/runtime-enforcer/internal/cgroups"
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
	return c.runInCgroup(command, args, true)
}

// runInCgroupHostMntNs runs the command in the cgroup WITHOUT unsharing the mount
// namespace, so it executes in the test process's own (host) mount namespace. It
// is used to exercise the runtime-bootstrap exclusion, which suppresses execs
// that run in the host mount namespace.
func (c cgroupInfo) runInCgroupHostMntNs(command string, args []string) error {
	return c.runInCgroup(command, args, false)
}

func (c cgroupInfo) runInCgroup(command string, args []string, freshMntNs bool) error {
	cmd := exec.Command(command, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		UseCgroupFD: true,
		CgroupFD:    c.fd,
	}
	if freshMntNs {
		// Run the workload in its own mount namespace so it resembles a real
		// container workload. Without this it would execute in the test process's
		// mount namespace (the host mount namespace), and the runtime-bootstrap
		// exclusion in enforce_cgroup_policy would suppress its exec event.
		// The new namespace is initialized with a copy of the current mount list,
		// so the binary, /tmp scripts and /proc/self/fd all remain resolvable.
		cmd.SysProcAttr.Unshareflags = syscall.CLONE_NEWNS
	}
	return cmd.Run()
}

func createTestCgroup(cgroupRoot string) (cgroupInfo, error) {
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
