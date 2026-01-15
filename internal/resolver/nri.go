package resolver

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"time"

	"github.com/containerd/nri/pkg/api"
	"github.com/containerd/nri/pkg/stub"
)

const (
	NRIReconnectWaitTime = time.Second * 1
	NRIConnectTimeout    = time.Second * 3
)

type plugin struct {
	stub     stub.Stub
	logger   *slog.Logger
	resolver *Resolver
}

func (p *plugin) StartContainer(
	ctx context.Context,
	pod *api.PodSandbox,
	container *api.Container,
) error {
	var err error
	defer func() {
		if err != nil {
			p.logger.ErrorContext(ctx, "failed to respond StartContainer hook", "error", err)
		}
	}()

	p.logger.DebugContext(
		ctx,
		"getting CreateContainer event",
		"container",
		container,
		"pod",
		pod,
	)

	err = p.resolver.AddPodFromNRI(ctx, pod, container)
	if err != nil {
		return fmt.Errorf("failed to add pod from NRI: %w", err)
	}

	return nil
}

// This would happen when container runtime restarts.
func (p *plugin) onClose() {
	p.logger.Info("Connection to the runtime lost...")
}

// StartNriPluginWithRetry creates a go routine and maintains a persistent connection with container runtime via NRI.
func (r *Resolver) StartNriPluginWithRetry(ctx context.Context, fn func(context.Context) error) error {
	d := net.Dialer{
		Timeout: NRIConnectTimeout,
	}
	conn, err := d.DialContext(ctx, "unix", r.nriSocketPath)
	if err != nil {
		return err
	}
	defer conn.Close()

	// now we know that NRI socket is available and listening.
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}
			err = fn(ctx)
			if err != nil {
				r.logger.Info("nri hook restarted", "error", err)
			}
			time.Sleep(NRIReconnectWaitTime)
		}
	}()
	return nil
}

func (r *Resolver) StartNriPlugin(ctx context.Context) error {
	var err error
	logger := r.logger.WithGroup("nri-hook")

	p := &plugin{
		logger:   logger,
		resolver: r,
	}

	opts := []stub.Option{
		stub.WithPluginIdx(r.nriPluginIndex),
		stub.WithSocketPath(r.nriSocketPath),
		stub.WithOnClose(p.onClose),
	}

	p.stub, err = stub.New(p, opts...)
	if err != nil {
		return fmt.Errorf("failed to create NRI plugin stub: %w", err)
	}

	err = p.stub.Run(ctx)
	if err != nil {
		return fmt.Errorf("NRI plugin exited with error: %w", err)
	}
	return nil
}
