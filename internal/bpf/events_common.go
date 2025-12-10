package bpf

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/cilium/ebpf/ringbuf"
)

// processRingbufEvents is a small helper used by both learning and monitoring loops.
// It reads events from the given ring buffer and sends them to the provided channel.
func (m *Manager) processRingbufEvents(ctx context.Context, rd *ringbuf.Reader, out chan<- ProcessEvent) error {
	// Goroutine to close the reader when context is done.
	go func() {
		<-ctx.Done()
		if err := rd.Close(); err != nil {
			m.logger.ErrorContext(ctx, "closing ringbuf reader", "error", err)
		}
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
			m.logger.ErrorContext(ctx, "parsing ringbuf event", "error", err)
			continue
		}

		// 4096 is the maximum supported path size in the eBPF program.
		const maxPathLen = 4096
		if header.PathLen > maxPathLen {
			m.logger.ErrorContext(ctx, "invalid path length in ringbuf event", "length", header.PathLen)
			continue
		}

		pathBytes := make([]byte, header.PathLen)
		if _, err = buf.Read(pathBytes); err != nil {
			m.logger.ErrorContext(ctx, "reading path bytes", "error", err)
			continue
		}

		out <- ProcessEvent{
			CgroupID:    header.Cgid,
			CgTrackerID: header.CgTrackerId,
			ExePath:     string(pathBytes),
		}
	}
}
