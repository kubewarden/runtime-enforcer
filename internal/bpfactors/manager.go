package bpfactors

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/neuvector/runtime-enforcer/internal/cgroups"
)

// todo!: we need to generate according to the architecture, not just x86

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cflags "-O2 -g -D__TARGET_ARCH_x86" -tags linux -type execve_event bpf ../../bpf/main.c -- -I/usr/include/

const (
	loadTimeConfigBPFVar = "load_time_config"
)

type Manager struct {
	logger             *slog.Logger
	objs               *bpfObjects
	violationEventChan chan bpfExecveEvent
	policyStringMaps   []*ebpf.Map
}

func getLoadTimeConfig() (*bpfLoadConf, error) {
	// First let's detect cgroupfs magic
	cgroupFsMagic, err := cgroups.DetectCgroupFSMagic()
	if err != nil {
		return nil, fmt.Errorf("cannot get cgroupfs magic: %w", err)
	}

	// This must be called before probing cgroup configurations
	if err = cgroups.DiscoverSubSysIds(); err != nil {
		return nil, fmt.Errorf("detection of Cgroup Subsystem Controllers failed: %w", err)
	}

	return &bpfLoadConf{
		CgrpFsMagic:     cgroupFsMagic,
		Cgrpv1SubsysIdx: cgroups.GetCgrpv1SubsystemIdx(),
		CgrpHierarchy:   cgroups.GetCgrpHierarchyID(),
		DebugMode:       0, // disable debug mode for now
	}, nil
}

func NewManager(logger *slog.Logger) (*Manager, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("failed to remove memlock: %w", err)
	}

	spec, err := loadBpf()
	if err != nil {
		return nil, fmt.Errorf("failed to load BPF spec: %w", err)
	}

	conf, err := getLoadTimeConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to get load time config: %w", err)
	}

	if err := spec.Variables[loadTimeConfigBPFVar].Set(conf); err != nil {
		return nil, fmt.Errorf("Error rewriting load_time_config: %w", err)
	}

	newLogger := logger.With("component", "ebpf-manager")
	newLogger.Info("Load time configuration detected",
		"cgrp_fs_magic", cgroups.CgroupFsMagicStr(conf.CgrpFsMagic),
		"cgrp_v1_subsys_idx", conf.Cgrpv1SubsysIdx,
		"cgrp_hierarchy_id", conf.CgrpHierarchy,
		"debug_mode", conf.DebugMode)

	// We just load the objects here so that we can pass the maps to other components but we don't load ebpf progs yet
	objs := bpfObjects{}
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		return nil, fmt.Errorf("Error loading objects: %w", err)
	}

	return &Manager{
		logger: newLogger,
		objs:   &objs,
		policyStringMaps: []*ebpf.Map{
			objs.PolStrMaps0,
			objs.PolStrMaps1,
			objs.PolStrMaps2,
			objs.PolStrMaps3,
			objs.PolStrMaps4,
			objs.PolStrMaps5,
			objs.PolStrMaps6,
			objs.PolStrMaps7,
			objs.PolStrMaps8,
			objs.PolStrMaps9,
			objs.PolStrMaps10,
		},
	}, nil
}

// GetLearner returns a new Learner instance associated with the BPF Manager.
// it should be called only if learning is enabled.
func GetLearner(m *Manager) *Learner {
	return newLearner(m.logger, m.objs.ExecveSend, m.objs.bpfMaps.RingbufExecve)
}

func (m *Manager) Start(ctx context.Context) error {
	defer func() {
		m.logger.InfoContext(ctx, "BPF Manager stopped")
		m.objs.Close()
	}()

	m.logger.InfoContext(ctx, "Starting BPF Manager...")
	// to understand: how we want to handle violations
	<-ctx.Done()
	return nil
}

// Expose some methods to interact with BPF maps
func (m *Manager) populatePolicyValue() func(policyID uint64, values []string) error {
	return func(policyID uint64, values []string) error {
		return m.generateBPFMaps(policyID, values)
	}
}
