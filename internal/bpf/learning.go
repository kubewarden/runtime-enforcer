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

func (m *Manager) GetLearningChannel() <-chan ProcessEvent {
	// if learning is not enabled, nobody will push events there
	return m.learningEventChan
}

func (m *Manager) learningStart(ctx context.Context) error {
	var execveLink link.Link
	defer func() {
		m.logger.InfoContext(ctx, "BPF Learner stopped")
		if execveLink != nil {
			execveLink.Close()
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

		m.learningEventChan <- ProcessEvent{
			CgroupID:    header.Cgid,
			CgTrackerID: header.CgTrackerId,
			ExePath:     string(pathBytes),
		}
	}
}
