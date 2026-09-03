package bpf

import (
	"fmt"
	"log/slog"

	"github.com/kubewarden/runtime-enforcer/internal/cgroups"
)

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
		DebugMode:       0, // disable debug mode for now
		LearningEnabled: learningEnabled,
	}

	logger.Info("bpf load config",
		"fs_magic_id", config.CgrpFsMagic,
		"v1_subsys_idx", config.Cgrpv1SubsysIdx,
		"debug_mode", config.DebugMode,
		"learning_enabled", config.LearningEnabled,
	)
	return config, nil
}
