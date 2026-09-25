package bpf

import (
	"fmt"
	"log/slog"

	"golang.org/x/sys/unix"

	"github.com/kubewarden/runtime-enforcer/internal/cgroups"
)

// hostInitMntNsPath is the procfs path whose mount namespace is used as the
// reference "host" namespace. With hostPID enabled (see the agent daemonset),
// PID 1 is the host init process, so its mount namespace is where the OCI
// runtime (containerd/shim/runc) runs. Runtime bootstrap execs (e.g. `runc
// init`) happen in this namespace before entering the container.
const hostInitMntNsPath = "/proc/1/ns/mnt"

// getHostMntNsInum returns the inode number of the host init mount namespace,
// which matches the kernel's ns_common.inum read in BPF. On failure it returns
// 0, which disables the runtime-bootstrap exclusion (fail-open: the previous
// behavior of reporting/enforcing every exec is preserved).
func getHostMntNsInum(logger *slog.Logger) uint64 {
	var st unix.Stat_t
	if err := unix.Stat(hostInitMntNsPath, &st); err != nil {
		logger.Warn("cannot stat host init mount namespace; runtime-bootstrap exclusion disabled",
			"path", hostInitMntNsPath,
			"error", err,
		)
		return 0
	}
	return st.Ino
}

func getLoadTimeConfig(logger *slog.Logger, enableLearning bool) (*bpfLoadConf, error) {
	cgInfo, err := cgroups.GetCgroupInfo()
	if err != nil {
		return nil, fmt.Errorf("cannot get cgroup info: %w", err)
	}

	logger.Info("cgroup info detected",
		"fs_magic", cgInfo.CgroupFsMagicString(),
		"v1_subsys_idx", cgInfo.CgroupV1SubsysIdx(),
		"resolution_path", cgInfo.CgroupResolutionPrefix(),
	)

	var learningEnabled uint8
	if enableLearning {
		learningEnabled = 1
	}

	config := &bpfLoadConf{
		CgrpFsMagic:     cgInfo.CgroupFsMagic(),
		Cgrpv1SubsysIdx: cgInfo.CgroupV1SubsysIdx(),
		HostMntNsInum:   getHostMntNsInum(logger),
		DebugMode:       0, // disable debug mode for now
		LearningEnabled: learningEnabled,
	}

	logger.Info("bpf load config",
		"fs_magic_id", config.CgrpFsMagic,
		"v1_subsys_idx", config.Cgrpv1SubsysIdx,
		"host_mnt_ns_inum", config.HostMntNsInum,
		"debug_mode", config.DebugMode,
		"learning_enabled", config.LearningEnabled,
	)
	return config, nil
}
