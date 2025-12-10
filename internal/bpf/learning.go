package bpf

import (
	"context"
	"fmt"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

func (m *Manager) GetLearningChannel() <-chan ProcessEvent {
	// if learning is not enabled, nobody will push events there
	return m.learningEventChan
}

func (m *Manager) learningStart(ctx context.Context) error {
	var execveLink link.Link
	defer func() {
		m.logger.InfoContext(ctx, "BPF Learner stopped")
		if execveLink != nil {
			if err := execveLink.Close(); err != nil {
				m.logger.ErrorContext(ctx, "closing execve link", "error", err)
			}
		}
	}()

	var err error
	execveLink, err = link.AttachTracing(link.TracingOptions{
		Program: m.objs.ExecveSend,
	})
	if err != nil {
		return fmt.Errorf("failed to attach execve tracing prog: %w", err)
	}

	rd, err := ringbuf.NewReader(m.objs.RingbufExecve)
	if err != nil {
		return fmt.Errorf("opening execve ringbuf reader: %w", err)
	}

	return m.processRingbufEvents(ctx, rd, m.learningEventChan)
}
