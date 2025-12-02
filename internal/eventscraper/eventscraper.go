package eventscraper

import (
	"context"

	"github.com/neuvector/runtime-enforcer/internal/bpfactors"
)

type EventScraper struct {
	learningChannel chan bpfactors.LearningEvent
}

func NewEventScraper(learningChannel chan bpfactors.LearningEvent) *EventScraper {
	return &EventScraper{
		learningChannel: learningChannel,
	}
}

func (es *EventScraper) Start(ctx context.Context) error {
	for {
		select {
		case <-ctx.Done():
			// Handle context cancellation
			return ctx.Err()

		case event := <-es.learningChannel:
			// We need to change the way we process the event
			// Process the event
			_ = event

			// No event to process
		}
	}
}
