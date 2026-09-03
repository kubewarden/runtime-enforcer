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
	cmd := exec.Command(command, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		UseCgroupFD: true,
		CgroupFD:    c.fd,
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
