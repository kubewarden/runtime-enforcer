package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/opencontainers/runtime-spec/specs-go"
	"github.com/rancher-sandbox/runtime-enforcer/internal/cgroups"
	"github.com/rancher-sandbox/runtime-enforcer/internal/ocihook"
)

type Config struct {
	SocketPath string
	Timeout    time.Duration
	FailOpen   bool
	LogLevel   string
	HookName   string
}

func findOCIConfig(logger *slog.Logger) (string, error) {
	var wd string
	var err error
	if wd, err = os.Getwd(); err != nil {
		logger.Warn("failed to retrieve working directory, using '.'", "error", err)
		wd = "."
	}
	configPaths := []string{
		"config.json",             // containerd (createRuntime)
		"../config.json",          // containerd (createContainer)
		"../userdata/config.json", // cri-o
	}

	configName := ""
	for _, path := range configPaths {
		p := filepath.Join(wd, path)
		if _, err = os.Stat(p); err == nil {
			configName = p
			break
		}
	}
	if configName == "" {
		logger.Error("fail to find spec file", "paths", configPaths, "cwd", wd)
		return "", errors.New("failed to find spec file")
	}
	return configName, nil
}

func readJSONSpec(fname string) (*specs.Spec, error) {
	var data []byte
	var err error
	if data, err = os.ReadFile(fname); err != nil {
		return nil, fmt.Errorf("failed to read %s: %w", fname, err)
	}

	var spec specs.Spec
	if err = json.Unmarshal(data, &spec); err != nil {
		return nil, fmt.Errorf("unmarshal failed: %w", err)
	}

	return &spec, nil
}

func resolveCgroup(spec *specs.Spec) (uint64, string, error) {
	if spec.Linux == nil || spec.Linux.CgroupsPath == "" {
		return 0, "", errors.New("linux or cgroupsPath missing in OCI spec")
	}
	cgPath, err := cgroups.ParseCgroupsPath(spec.Linux.CgroupsPath)
	if err != nil {
		return 0, "", err
	}
	cgInfo, err := cgroups.GetCgroupInfo()
	if err != nil {
		return 0, "", fmt.Errorf("cgroup detection: %w", err)
	}
	fullPath := filepath.Join(cgInfo.CgroupResolutionPrefix(), cgPath)
	trackedID, err := cgroups.GetCgroupIDFromPath(fullPath)
	if err != nil {
		return 0, "", err
	}
	return trackedID, fullPath, nil
}

func runCreateRuntime(logger *slog.Logger, cfg Config) error {
	configPath, err := findOCIConfig(logger)
	if err != nil {
		return err
	}
	spec, err := readJSONSpec(configPath)
	if err != nil {
		return fmt.Errorf("read OCI spec %s: %w", configPath, err)
	}
	cgID, cgPath, err := resolveCgroup(spec)
	if err != nil {
		return fmt.Errorf("resolve cgroup: %w", err)
	}

	req := ocihook.HookRequest{
		CgroupID:   cgID,
		CgroupPath: cgPath,
	}
	if cfg.SocketPath == "" {
		return errors.New("agent socket path is empty")
	}
	err = ocihook.NotifyAgentWithRetry(cfg.SocketPath, req, cfg.Timeout)
	if err != nil && cfg.FailOpen {
		logger.Warn("notify failed (fail-open)", "error", err)
		return nil
	}
	return err
}

func main() {
	var cfg Config
	flag.StringVar(&cfg.SocketPath, "socket", "/var/run/oci/oci-hook.sock", "OCI socket path")
	flag.DurationVar(
		&cfg.Timeout,
		"timeout",
		ocihook.DefaultNotifyAgentTimeout,
		"Max time to wait for agent acknowledgement",
	)
	flag.BoolVar(&cfg.FailOpen, "fail-open", false, "If notifying the agent fails, log and exit 0")
	flag.StringVar(&cfg.LogLevel, "log-level", "info", "Log level: debug, info, warn, error")
	flag.Parse()

	var logLevel slog.Level
	if err := logLevel.UnmarshalText([]byte(cfg.LogLevel)); err != nil {
		logLevel = slog.LevelInfo
	}
	slogHandler := slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: logLevel})
	logger := slog.New(slogHandler).With("component", "oci-hook")

	args := flag.Args()
	if len(args) != 1 {
		logger.Error("missing hook name", "args", args)
		os.Exit(1)
	}
	cfg.HookName = args[0]

	switch cfg.HookName {
	case "createRuntime":
		if err := runCreateRuntime(logger, cfg); err != nil {
			logger.Error("createRuntime hook failed", "error", err)
			os.Exit(1)
		}
	case "createContainer", "poststart", "poststop", "startContainer", "prestart":
		// Reserved for future use; do not block container start.
	default:
		logger.Warn("unknown hook name, ignoring", "hook", cfg.HookName)
	}
}
