package bpf

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
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
			fmodRetProg.Close()
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

	// Goroutine to close the reader when context is done
	go func() {
		<-ctx.Done()
		rd.Close()
	}()

	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				m.logger.InfoContext(ctx, "ringbuf reader closed")
				return nil
			}
			return fmt.Errorf("reading from reader: %w", err)
		}

		ev := bpfProcessEvt{}

		// Parse the ringbuf event entry into a bpfEvent structure.
		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &ev); err != nil {
			m.logger.ErrorContext(ctx, "parsing ringbuf event:", "error", err)
			continue
		}

		m.monitoringEventChan <- ProcessEvent{
			CgroupID:    ev.Cgid,
			CgTrackerID: ev.CgTrackerId,
			Comm:        ev.Comm,
		}
	}
}
