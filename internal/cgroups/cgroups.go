package cgroups

import "bytes"

const (
	// CgroupUnsetValue is a generic unset value that means undefined or not set.
	CgroupUnsetValue = 0

	// CgroupSubsysCount is the max cgroup subsystems count used from BPF side
	// to define a max index for the default controllers on tasks.
	// For further documentation check the BPF part.
	CgroupSubsysCount = 15

	// CgroupDefaultHierarchy is the default hierarchy for cgroupv2.
	CgroupDefaultHierarchy = 0
)

type CgroupModeCode int

const (
	/* Cgroup Mode:
	 * https://systemd.io/CGROUP_DELEGATION/
	 * But this should work also for non-systemd environments: where
	 * only legacy or unified are available by default.
	 */

	CgroupUndef   CgroupModeCode = iota
	CgroupLegacy  CgroupModeCode = 1
	CgroupHybrid  CgroupModeCode = 2
	CgroupUnified CgroupModeCode = 3
)

type DeploymentCode int

const (
	// DeploymentUnknown is the default deployment mode.
	DeploymentUnknown DeploymentCode = iota
	// DeploymentK8s is Kubernetes deployment.
	DeploymentK8s DeploymentCode = 1
	// DeploymentContainer is container deployment, e.g. docker or podman.
	DeploymentContainer DeploymentCode = 2
	// DeploymentSystemdService is systemd service deployment.
	DeploymentSystemdService DeploymentCode = 10
	// DeploymentSystemdUser is systemd user-session deployment.
	DeploymentSystemdUser DeploymentCode = 11
)

func (op DeploymentCode) String() string {
	return [...]string{
		DeploymentUnknown:        "unknown",
		DeploymentK8s:            "Kubernetes",
		DeploymentContainer:      "Container",
		DeploymentSystemdService: "systemd service",
		DeploymentSystemdUser:    "systemd user session",
	}[op]
}

// CgroupNameFromCStr returns a Go string from the passed C language format string.
func CgroupNameFromCStr(cstr []byte) string {
	i := bytes.IndexByte(cstr, 0)
	if i == -1 {
		i = len(cstr)
	}
	return string(cstr[:i])
}
