package bpfactors

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

const (
	learningEventChanSize = 100
	CommSize              = 16
)

type LearningEvent struct {
	CgroupID    uint64
	CgTrackerID uint64
	Comm        [CommSize]int8
}

type Learner struct {
	logger         *slog.Logger
	learnEventChan chan LearningEvent
	execveProg     *ebpf.Program
	ringbufExecve  *ebpf.Map
}

// We should move the learner inside the manager.
func newLearner(logger *slog.Logger, execveSend *ebpf.Program, ringbufExecve *ebpf.Map) *Learner {
	return &Learner{
		logger:         logger.With("component", "bpf-learner"),
		learnEventChan: make(chan LearningEvent, learningEventChanSize),
		execveProg:     execveSend,
		ringbufExecve:  ringbufExecve,
	}
}

func (l *Learner) Start(ctx context.Context) error {
	var execveLink link.Link

	defer func() {
		l.logger.InfoContext(ctx, "BPF Learner stopped")
		if execveLink != nil {
			execveLink.Close()
		}
	}()

	l.logger.InfoContext(ctx, "Enable BPF learner...")

	var err error
	execveLink, err = link.AttachTracing(link.TracingOptions{
		Program: l.execveProg,
	})
	if err != nil {
		return fmt.Errorf("failed to attach execve tracing prog: %w", err)
	}

	rd, err := ringbuf.NewReader(l.ringbufExecve)
	if err != nil {
		return fmt.Errorf("opening execve ringbuf reader: %w", err)
	}

	go func() {
		<-ctx.Done()
		rd.Close()
	}()

	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				l.logger.InfoContext(ctx, "ringbuf reader closed")
				return nil
			}
			return fmt.Errorf("reading from reader: %w", err)
		}

		ev := bpfExecveEvent{}

		// Parse the ringbuf event entry into a bpfEvent structure.
		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &ev); err != nil {
			l.logger.ErrorContext(ctx, "parsing ringbuf event:", "error", err)
			continue
		}

		l.learnEventChan <- LearningEvent{
			CgroupID:    ev.Info.Cgid,
			CgTrackerID: ev.Info.CgTrackerId,
			Comm:        ev.Comm,
		}
	}
}

func (l *Learner) GetLearningChannel() chan LearningEvent {
	return l.learnEventChan
}
