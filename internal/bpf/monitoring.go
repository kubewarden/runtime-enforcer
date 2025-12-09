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

		buf := bytes.NewBuffer(record.RawSample)
		var header bpfEventHeader
		if err := binary.Read(buf, binary.LittleEndian, &header); err != nil {
			m.logger.ErrorContext(ctx, "parsing ringbuf event:", "error", err)
			continue
		}

		if header.PathLen > 4096 {
			m.logger.ErrorContext(ctx, "invalid path length in ringbuf event:", "length", header.PathLen)
			continue
		}

		pathBytes := make([]byte, header.PathLen)
		_, err = buf.Read(pathBytes)
		if err != nil {
			m.logger.ErrorContext(ctx, "reading path bytes:", "error", err)
			continue
		}

		m.monitoringEventChan <- ProcessEvent{
			CgroupID:    header.Cgid,
			CgTrackerID: header.CgTrackerId,
			ExePath:     string(pathBytes),
		}
	}
}
