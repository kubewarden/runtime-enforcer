package nri

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"time"

	retry "github.com/avast/retry-go/v4"
	"github.com/containerd/nri/pkg/stub"
	"github.com/kubewarden/runtime-enforcer/internal/resolver"
)

const (
	maxDelay = time.Minute * 1
)

type Handler struct {
	socketPath  string
	pluginIndex string
	logger      *slog.Logger
	resolver    *resolver.Resolver
}

func newNRIPlugin(
	logger *slog.Logger,
	resolver *resolver.Resolver,
	opts ...stub.Option,
) (*plugin, error) {
	var err error
	p := &plugin{
		logger:          logger.With("component", "nri-plugin"),
		resolver:        resolver,
		failOpen:        os.Getenv("NRI_FAILOPEN") == "true",
		resolveCgroupID: cgroupFromContainer,
	}

	p.stub, err = stub.New(p, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create NRI plugin stub: %w", err)
	}
	return p, nil
}

func (p *plugin) Run(ctx context.Context) error {
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			p.stub.Stop()
		case <-done:
		}
	}()

	err := p.stub.Run(ctx)
	close(done) // prevent goroutine leak if Run() returns naturally

	if ctx.Err() != nil {
		return ctx.Err()
	}
	return err
}

func NewNRIHandler(
	socketPath, pluginIndex string,
	logger *slog.Logger,
	r *resolver.Resolver,
) (*Handler, error) {
	h := &Handler{
		socketPath:  socketPath,
		pluginIndex: pluginIndex,
		logger:      logger.With("component", "nri-handler"),
		resolver:    r,
	}
	if err := h.checkNRISupport(); err != nil {
		return nil, fmt.Errorf("NRI support check failed: %w", err)
	}
	return h, nil
}

func (h *Handler) checkNRISupport() error {
	const (
		connectionTimeout = 3 * time.Second
		attempts          = 5
	)

	tryConnect := func() error {
		h.logger.Info("connecting to NRI socket")
		d := net.Dialer{
			Timeout: connectionTimeout,
		}
		conn, err := d.DialContext(context.Background(), "unix", h.socketPath)
		if err != nil {
			return err
		}
		_ = conn.Close()
		return nil
	}
	return retry.Do(
		tryConnect,
		retry.Attempts(attempts),
		retry.Delay(time.Second),
		retry.DelayType(retry.BackOffDelay),
		retry.OnRetry(func(n uint, err error) {
			// n = 0 for the first retry
			h.logger.Warn("error during NRI socket connection, retrying...",
				"attempt", n+1,
				"error", err,
			)
		}),
	)
}

func (h *Handler) startNRIPlugin(ctx context.Context) error {
	p, err := newNRIPlugin(
		h.logger,
		h.resolver,
		stub.WithLogger(newNRILogger(h.logger)),
		stub.WithPluginName("runtime-enforcer-agent"),
		stub.WithPluginIdx(h.pluginIndex),
		stub.WithSocketPath(h.socketPath),
	)
	if err != nil {
		return fmt.Errorf("failed to create NRI plugin: %w", err)
	}

	err = p.Run(ctx)
	if err != nil {
		if p.lastErr != nil {
			// We use the lastErr whenever possible, because the error returned by p.Run()
			// is usually not very helpful, e.g., `ttrpc: server closed`.
			err = p.lastErr
		}
		return fmt.Errorf("NRI plugin exited with error: %w", err)
	}
	return nil
}

func (h *Handler) Start(ctx context.Context) error {
	defer func() {
		h.logger.InfoContext(ctx, "NRI handler has stopped")
	}()

	// isRetryable is called only in case of err != nil
	isRetryable := func(err error) bool {
		// We stop in case of:
		// - context.Canceled/DeadlineExceeded
		if errors.Is(err, context.Canceled) ||
			errors.Is(err, context.DeadlineExceeded) {
			return false
		}
		return true
	}

	return retry.Do(
		func() error {
			return h.startNRIPlugin(ctx)
		},
		retry.Context(ctx),
		retry.Attempts(0), // infinite attempts
		retry.Delay(time.Second),
		retry.DelayType(retry.BackOffDelay),
		retry.MaxDelay(maxDelay),
		retry.RetryIf(isRetryable),
		retry.OnRetry(func(n uint, err error) {
			// n = 0 for the first retry
			h.logger.WarnContext(ctx, "error during NRI plugin execution, retrying...",
				"attempt", n+1,
				"error", err,
			)
		}),
	)
}
