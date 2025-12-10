package bpf

import (
	"context"
	"fmt"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

func (m *Manager) GetMonitoringChannel() <-chan ProcessEvent {
	return m.monitoringEventChan
}

func (m *Manager) monitoringStart(ctx context.Context) error {
	var fmodRetProg link.Link
	defer func() {
		m.logger.InfoContext(ctx, "BPF Monitor stopped")
		if fmodRetProg != nil {
			if err := fmodRetProg.Close(); err != nil {
				m.logger.ErrorContext(ctx, "closing fmodRetProg link", "error", err)
			}
		}
	}()

	var err error
	fmodRetProg, err = link.AttachTracing(link.TracingOptions{
		Program: m.objs.EnforceCgroupPolicy,
	})
	if err != nil {
		return fmt.Errorf("failed to attach fmodRetProg tracing prog: %w", err)
	}

	rd, err := ringbuf.NewReader(m.objs.RingbufMonitoring)
	if err != nil {
		return fmt.Errorf("opening monitoring ringbuf reader: %w", err)
	}

	return m.processRingbufEvents(ctx, rd, m.monitoringEventChan)
}
