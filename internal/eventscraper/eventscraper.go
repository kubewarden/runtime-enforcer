package eventscraper

import (
	"context"
	"log/slog"

	"github.com/neuvector/runtime-enforcer/internal/bpf"
	"github.com/neuvector/runtime-enforcer/internal/resolver"
)

type EventScraper struct {
	learningChannel   <-chan bpf.ProcessEvent
	monitoringChannel <-chan bpf.ProcessEvent
	logger            *slog.Logger
	resolver          *resolver.Resolver
}

func NewEventScraper(learningChannel <-chan bpf.ProcessEvent, monitoringChannel <-chan bpf.ProcessEvent, logger *slog.Logger, resolver *resolver.Resolver) *EventScraper {
	return &EventScraper{
		learningChannel:   learningChannel,
		monitoringChannel: monitoringChannel,
		logger:            logger,
		resolver:          resolver,
	}
}

// todo!: we should also send the initial state of the processes running on the system. We could use BPF iterators for that.
func (es *EventScraper) Start(ctx context.Context) error {
	for {
		select {
		case <-ctx.Done():
			// Handle context cancellation
			return nil

		case event := <-es.learningChannel:
			// todo!: manage cgroups on the host! how should we ignore them?
			cgIDLookup := event.CgTrackerID
			// this could happen if the resolver has not yet seen the pod or it was not able to scrape the container info
			if cgIDLookup == 0 {
				// es.logger.Warn("learning event with empty cgIDTracker, falling back to cgroupID", "cgID", event.CgroupID)
				if event.CgroupID == 0 {
					es.logger.Warn("learning event with empty cgroupID too, skipping event")
					continue
				}
				cgIDLookup = event.CgroupID
			}
			info, err := es.resolver.GetKubeInfo(cgIDLookup)
			if err != nil {
				// es.logger.Warn("failed to get kube info for learning event", "cgID", cgIDLookup, "error", err)
				continue
			}
			// todo!: we need to send this info to the learning controller
			es.logger.Info("learning event", "comm", event.ExePath, "cgID", event.CgTrackerID, "info", info)

		case event := <-es.monitoringChannel:
			cgIDLookup := event.CgTrackerID
			// this could happen if the resolver has not yet seen the pod or it was not able to scrape the container info
			if cgIDLookup == 0 {
				// es.logger.Warn("monitoring event with empty cgIDTracker, falling back to cgroupID", "cgID", event.CgroupID)
				if event.CgroupID == 0 {
					es.logger.Warn("monitoring event with empty cgroupID too, skipping event")
					continue
				}
				cgIDLookup = event.CgroupID
			}
			info, err := es.resolver.GetKubeInfo(cgIDLookup)
			if err != nil {
				// es.logger.Warn("failed to get kube info for monitoring event", "cgID", cgIDLookup, "error", err)
				continue
			}
			// todo!: we need to send this info to OTEL
			es.logger.Info("monitoring event", "comm", event.ExePath, "cgID", event.CgTrackerID, "info", info)
		}
	}
}
