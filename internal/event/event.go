package event

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"log/slog"
)

type AggregatableEvent interface {
	GetExecutablePath() string
	Hash() string
	Aggregate(AggregatableEvent) error
	GetProposalName() (string, error)
	GetNamespace() string
}

type Aggregator interface {
	HandleEvent(e AggregatableEvent) error
	Flush(func(AggregatableEvent) (bool, error)) error
}

type LocalEventAggregator struct {
	lock sync.Mutex

	logger *slog.Logger

	aggregatedEvents map[string]AggregatableEvent
}

func CreateEventAggregator(logger *slog.Logger) Aggregator {
	return &LocalEventAggregator{
		logger:           logger.With("component", "event_aggregator"),
		aggregatedEvents: make(map[string]AggregatableEvent),
	}
}

func (l *LocalEventAggregator) HandleEvent(e AggregatableEvent) error {
	l.lock.Lock()
	defer l.lock.Unlock()

	h := e.Hash()
	if ae, ok := l.aggregatedEvents[h]; ok {
		if err := ae.Aggregate(e); err != nil {
			return fmt.Errorf("failed to aggregate an event: %w", err)
		}
	} else {
		l.aggregatedEvents[h] = e
	}
	return nil
}

// TODO: performance benchmark
func (l *LocalEventAggregator) Flush(flushFunc func(AggregatableEvent) (bool, error)) error {
	l.lock.Lock()
	defer l.lock.Unlock()

	for k, v := range l.aggregatedEvents {
		cont, err := flushFunc(v)
		if err != nil {
			l.logger.WarnContext(context.Background(), "failed to handle an event", "error", err)
		}
		if !cont {
			return errors.New("operation cancelled")
		}
		delete(l.aggregatedEvents, k)
	}

	return nil
}
