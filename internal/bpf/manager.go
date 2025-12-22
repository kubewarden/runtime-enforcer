package bpf

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/features"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/neuvector/runtime-enforcer/internal/cgroups"
	"github.com/neuvector/runtime-enforcer/internal/kernels"

	"golang.org/x/sync/errgroup"
)

// todo!: we need to generate according to the architecture, not just x86

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cflags "-O2 -g -D__TARGET_ARCH_x86" -tags linux -target bpfel -type process_evt bpf ../../bpf/main.c -- -I/usr/include/

const (
	loadTimeConfigBPFVar = "load_time_config"
	policyMap8Name       = "pol_str_maps_8"
	policyMap9Name       = "pol_str_maps_9"
	policyMap10Name      = "pol_str_maps_10"
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
	Mode        string
}

type bpfEventHeader struct {
	Cgid        uint64
	CgTrackerID uint64
	PathLen     uint16
	Mode        uint8
}

type Manager struct {
	logger           *slog.Logger
	objs             *bpfObjects
	policyStringMaps []*ebpf.Map
	pinPath          string

	// Learning
	enableLearning    bool
	learningEventChan chan ProcessEvent

	// Monitoring
	monitoringEventChan chan ProcessEvent

	// Kernel version check cache
	kernelCheckOnce sync.Once
	isPre5_9        bool
}

func probeEbpfFeatures() error {
	// For now known requirements are:
	// - BPF_MAP_TYPE_RINGBUF
	// - tracing prog with attach type BPF_MODIFY_RETURN

	// Check for BPF_MAP_TYPE_RINGBUF
	if err := features.HaveMapType(ebpf.RingBuf); err != nil {
		return fmt.Errorf("BPF_MAP_TYPE_RINGBUF not supported: %w", err)
	}

	// Check for BPF_MODIFY_RETURN attach type
	// Today there is no an helper function for attach type BPF_MODIFY_RETURN so we do it by hand.
	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Name: "probe_fmodret",
		Type: ebpf.Tracing,
		Instructions: asm.Instructions{
			asm.Mov.Imm(asm.R0, 0),
			asm.Return(),
		},
		AttachType: ebpf.AttachModifyReturn,
		License:    "MIT",
		AttachTo:   "security_bprm_creds_for_exec",
	})
	if err != nil {
		return err
	}
	defer prog.Close()

	link, err := link.AttachTracing(link.TracingOptions{
		Program: prog,
	})
	if err != nil {
		return err
	}
	err = link.Close()
	if err != nil {
		return err
	}

	return nil
}

// verifyBPFMount checks if the given path is mounted as bpffs.
func verifyBPFMount(path string) error {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(path, &stat); err != nil {
		return fmt.Errorf("failed to stat path %s: %w", path, err)
	}
	// BPF_FS_MAGIC = 0xcafe4a11
	const bpfFSMagic = 0xcafe4a11
	if stat.Type != bpfFSMagic {
		return fmt.Errorf("path %s is not a bpf filesystem (type: 0x%x)", path, stat.Type)
	}
	return nil
}

// mountBPFFS mounts a BPF filesystem at the given path.
func mountBPFFS(path string, logger *slog.Logger) error {
	// Create the directory if it doesn't exist
	if err := os.MkdirAll(path, 0750); err != nil {
		return fmt.Errorf("failed to create mount directory: %w", err)
	}

	// Check if already mounted
	if err := verifyBPFMount(path); err == nil {
		logger.Info("BPF filesystem already mounted", "path", path)
		return nil
	}

	// Mount the BPF filesystem
	// syscall.Mount(source, target, fstype, flags, data)
	if err := syscall.Mount("bpffs", path, "bpf", 0, "mode=0750"); err != nil {
		return fmt.Errorf("failed to mount BPF filesystem at %s: %w", path, err)
	}

	logger.Info("Successfully mounted BPF filesystem", "path", path)
	return nil
}

func NewManager(
	logger *slog.Logger,
	enableLearning bool,
	eBPFLogLevel ebpf.LogLevel,
	pinPath string,
) (*Manager, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("failed to remove memlock: %w", err)
	}

	logger.Info("Probing eBPF features...")
	if err := probeEbpfFeatures(); err != nil {
		return nil, fmt.Errorf("failure during eBPF feature probing: %w", err)
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
		"cgrp_fs_magic", cgroups.CgroupFsMagicString(conf.CgrpFsMagic),
		"cgrp_v1_subsys_idx", conf.Cgrpv1SubsysIdx,
		"debug_mode", conf.DebugMode)

	// Only kernels >= 5.11 support hash key lengths > 512 bytes
	// https://github.com/cilium/tetragon/commit/834b5fe7d4063928cf7b89f61252637d833ca018
	// so we reduce the key size for older kernels, these maps won't be used anyway
	if kernels.CurrVersionIsLowerThan("5.11") {
		for _, mapName := range []string{policyMap8Name, policyMap9Name, policyMap10Name} {
			policyMap, ok := spec.Maps[mapName]
			if !ok {
				return nil, fmt.Errorf("map %s not found in spec", mapName)
			}
			// Entries should be already set to 1 in the spec, but just in case
			policyMap.MaxEntries = 1
			if policyMap.InnerMap == nil {
				return nil, fmt.Errorf("map %s is not a hash of maps", mapName)
			}
			// this is the max key size supported on older kernels
			policyMap.InnerMap.KeySize = stringMapSize7
		}
	}

	// Mount BPF filesystem and enable pinning
	if pinPath != "" {
		// Mount the BPF filesystem at the specified path
		if err = mountBPFFS(pinPath, newLogger); err != nil {
			return nil, fmt.Errorf("failed to mount BPF filesystem: %w", err)
		}
		newLogger.Info("BPF map pinning enabled", "pin_path", pinPath)
	}

	// We just load the objects here so that we can pass the maps to other components but we don't load ebpf progs yet
	objs := bpfObjects{}
	opts := &ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{
			LogLevel: eBPFLogLevel,
		},
		Maps: ebpf.MapOptions{
			PinPath: pinPath, // Enable automatic pinning for all maps
		},
	}
	if err = spec.LoadAndAssign(&objs, opts); err != nil {
		return nil, fmt.Errorf("error loading objects: %w", err)
	}

	return &Manager{
		logger:              newLogger,
		objs:                &objs,
		pinPath:             pinPath,
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

func (m *Manager) isKernelPre5_9() bool {
	m.kernelCheckOnce.Do(func() {
		m.isPre5_9 = kernels.CurrVersionIsLowerThan("5.9")
	})
	return m.isPre5_9
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
