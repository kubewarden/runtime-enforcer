package bpf

import (
	"fmt"
	"log/slog"

	"github.com/neuvector/runtime-enforcer/internal/cgroups"
)

func getLoadTimeConfig(logger *slog.Logger) (*bpfLoadConf, error) {
	// First let's detect cgroupfs magic
	cgroupFsMagic, err := cgroups.DetectCgroupFSMagic(logger)
	if err != nil {
		return nil, fmt.Errorf("cannot get cgroupfs magic: %w", err)
	}

	// This must be called before probing cgroup configurations
	if err = cgroups.DiscoverSubSysIDs(logger); err != nil {
		return nil, fmt.Errorf("detection of Cgroup Subsystem Controllers failed: %w", err)
	}

	return &bpfLoadConf{
		CgrpFsMagic:     cgroupFsMagic,
		Cgrpv1SubsysIdx: cgroups.GetCgrpv1SubsystemIdx(),
		DebugMode:       0, // disable debug mode for now
	}, nil
}
