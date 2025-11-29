package controller

import (
	"context"

	"k8s.io/client-go/util/workqueue"
	"sigs.k8s.io/controller-runtime/pkg/event"
)

// MockEvent is an empty event used by the WorkloadPolicyStatusController to start the initial reconciliation.
type MockEvent struct {
}

// MockEventHandler implements handler.TypedEventHandler[MockEvent, MockEvent].
type MockEventHandler struct {
}

func (e MockEventHandler) Create(
	_ context.Context,
	_ event.TypedCreateEvent[MockEvent],
	_ workqueue.TypedRateLimitingInterface[MockEvent],
) {

}

func (e MockEventHandler) Update(
	_ context.Context,
	_ event.TypedUpdateEvent[MockEvent],
	_ workqueue.TypedRateLimitingInterface[MockEvent],
) {

}

func (e MockEventHandler) Delete(
	_ context.Context,
	_ event.TypedDeleteEvent[MockEvent],
	_ workqueue.TypedRateLimitingInterface[MockEvent],
) {

}

func (e MockEventHandler) Generic(
	_ context.Context,
	evt event.TypedGenericEvent[MockEvent],
	q workqueue.TypedRateLimitingInterface[MockEvent],
) {
	q.AddRateLimited(evt.Object)
}
