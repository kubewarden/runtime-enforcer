package bpf

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/neuvector/runtime-enforcer/internal/cgroups"
	"golang.org/x/sync/errgroup"
)

// todo!: we need to generate according to the architecture, not just x86

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cflags "-O2 -g -D__TARGET_ARCH_x86" -tags linux -type process_evt bpf ../../bpf/main.c -- -I/usr/include/

const (
	loadTimeConfigBPFVar = "load_time_config"
)

const (
	// 100 should be enough to avoid blocking in normal conditions, let's monitor this later.
	learningEventChanSize = 100
	monitorEventChanSize  = 100
)

// ProcessEvent represents an event coming from BPF programs, for now used for learning and monitoring.
type ProcessEvent struct {
	CgroupID    uint64
	CgTrackerID uint64
	ExePath     string
}

type bpfEventHeader struct {
	Cgid        uint64
	CgTrackerID uint64
	PathLen     uint16
}

type Manager struct {
	logger           *slog.Logger
	objs             *bpfObjects
	policyStringMaps []*ebpf.Map

	// Learning
	enableLearning    bool
	learningEventChan chan ProcessEvent

	// Monitoring
	monitoringEventChan chan ProcessEvent
}

func NewManager(logger *slog.Logger, enableLearning bool, eBPFLogLevel ebpf.LogLevel) (*Manager, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("failed to remove memlock: %w", err)
	}

	spec, err := loadBpf()
	if err != nil {
		return nil, fmt.Errorf("failed to load BPF spec: %w", err)
	}

	conf, err := getLoadTimeConfig(logger)
	if err != nil {
		return nil, fmt.Errorf("failed to get load time config: %w", err)
	}

	if err = spec.Variables[loadTimeConfigBPFVar].Set(conf); err != nil {
		return nil, fmt.Errorf("error rewriting load_time_config: %w", err)
	}

	newLogger := logger.With("component", "ebpf-manager")
	newLogger.Info("Load time configuration detected",
		"cgrp_fs_magic", cgroups.CgroupFsMagicStr(conf.CgrpFsMagic),
		"cgrp_v1_subsys_idx", conf.Cgrpv1SubsysIdx,
		"debug_mode", conf.DebugMode)

	// We just load the objects here so that we can pass the maps to other components but we don't load ebpf progs yet
	objs := bpfObjects{}
	opts := &ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{
			LogLevel: eBPFLogLevel,
		},
	}
	if err = spec.LoadAndAssign(&objs, opts); err != nil {
		return nil, fmt.Errorf("error loading objects: %w", err)
	}

	return &Manager{
		logger:              newLogger,
		objs:                &objs,
		enableLearning:      enableLearning,
		learningEventChan:   make(chan ProcessEvent, learningEventChanSize),
		monitoringEventChan: make(chan ProcessEvent, monitorEventChanSize),
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

func (m *Manager) Start(ctx context.Context) error {
	defer func() {
		m.logger.InfoContext(ctx, "BPF Manager stopped")
		if err := m.objs.Close(); err != nil {
			m.logger.ErrorContext(ctx, "failed to close BPF objects", "error", err)
		}
	}()

	m.logger.InfoContext(ctx, "Starting BPF Manager...")
	g, ctx := errgroup.WithContext(ctx)

	// Cgroup Tracker
	g.Go(func() error {
		return m.cgroupTrackerStart(ctx)
	})

	// Learning
	if m.enableLearning {
		g.Go(func() error {
			return m.learningStart(ctx)
		})
	}

	// Monitoring
	g.Go(func() error {
		return m.monitoringStart(ctx)
	})

	if err := g.Wait(); err != nil {
		return fmt.Errorf("BPF Manager error: %w", err)
	}
	return nil
}
