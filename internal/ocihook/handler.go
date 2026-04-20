package ocihook

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"

	"github.com/go-logr/logr"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

type HookRequest struct {
	CgroupID   uint64 `json:"cgroupId"`
	CgroupPath string `json:"cgroupPath"`
}

type HookResponse struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

type Handler struct {
	socketPath        string
	cgTrackerUpdateFn func(cgID uint64, cgroupPath string) error
}

func NewHandler(
	socketPath string,
	cgTrackerUpdateFn func(cgID uint64, cgroupPath string) error,
) *Handler {
	return &Handler{
		socketPath:        socketPath,
		cgTrackerUpdateFn: cgTrackerUpdateFn,
	}
}

// Start implements the controller-runtime Runnable interface.
func (h *Handler) Start(ctx context.Context) error {
	logger := log.FromContext(ctx).WithValues("socket", h.socketPath)

	dir := filepath.Dir(h.socketPath)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return fmt.Errorf("failed to create socket directory %q: %w", dir, err)
	}

	// Ensure the socket does not already exist.
	if err := os.RemoveAll(h.socketPath); err != nil {
		return fmt.Errorf("failed to remove existing socket %q: %w", h.socketPath, err)
	}

	var lc net.ListenConfig
	l, err := lc.Listen(ctx, "unix", h.socketPath)
	if err != nil {
		return fmt.Errorf("failed to listen on unix socket %q: %w", h.socketPath, err)
	}

	logger.Info("OCI hook handler listening")

	defer func() {
		_ = l.Close()
		_ = os.RemoveAll(h.socketPath)
		logger.Info("OCI hook handler stopped")
	}()

	go func() {
		<-ctx.Done()
		_ = l.Close()
	}()

	for {
		conn, acceptErr := l.Accept()
		if acceptErr != nil {
			if ctx.Err() != nil {
				return nil
			}
			logger.Error(acceptErr, "failed to accept OCI hook connection")
			continue
		}

		go h.handleConn(ctx, conn)
	}
}

func (h *Handler) handleConn(ctx context.Context, conn net.Conn) {
	logger := log.FromContext(ctx)
	defer conn.Close()

	br := bufio.NewReader(conn)

	var req HookRequest
	if err := json.NewDecoder(br).Decode(&req); err != nil {
		logger.Error(err, "failed to decode OCI hook request")
		writeHookResponse(logger, conn, false, fmt.Sprintf("decode request: %v", err))
		return
	}

	if req.CgroupID == 0 || req.CgroupPath == "" {
		logger.Error(
			nil,
			"invalid OCI hook request",
			"cgroupId", req.CgroupID,
			"cgroupPath", req.CgroupPath,
		)
		writeHookResponse(logger, conn, false, "invalid cgroupId or cgroupPath")
		return
	}

	if err := h.cgTrackerUpdateFn(req.CgroupID, req.CgroupPath); err != nil {
		logger.Error(err, "failed to update cgroup tracker from OCI hook",
			"cgroupId", req.CgroupID,
			"cgroupPath", req.CgroupPath,
		)
		writeHookResponse(logger, conn, false, fmt.Sprintf("cgroup tracker update failed: %v", err))
		return
	}

	logger.Info("processed OCI hook request",
		"cgroupId", req.CgroupID,
		"cgroupPath", req.CgroupPath,
	)
	writeHookResponse(logger, conn, true, "")
}

func writeHookResponse(logger logr.Logger, conn net.Conn, ok bool, errMsg string) {
	resp := HookResponse{OK: ok}
	if !ok {
		resp.Error = errMsg
	}
	if err := json.NewEncoder(conn).Encode(resp); err != nil {
		logger.Error(err, "failed to encode OCI hook response")
	}
}
