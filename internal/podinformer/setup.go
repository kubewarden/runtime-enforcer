package podinformer

import (
	"log/slog"

	"github.com/neuvector/runtime-enforcer/internal/resolver"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/tools/cache"
)

// EventHandlers returns the event handlers for pod events.
func EventHandlers(log *slog.Logger, r *resolver.Resolver) cache.ResourceEventHandler {
	return cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			pod, ok := obj.(*corev1.Pod)
			if !ok {
				log.Error("add-pod handler: unexpected object type", "object", obj)
				return
			}
			log.Debug(
				"add-pod handler called",
				"pod-name", pod.Name,
				"pod-namespace", pod.Namespace,
				"pod-uid", string(pod.UID),
			)
			r.addPod(pod)
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			oldPod, ok := oldObj.(*corev1.Pod)
			if !ok {
				log.Error("update-pod handler: unexpected object type", "old object", oldObj)
				return
			}
			newPod, ok := newObj.(*corev1.Pod)
			if !ok {
				log.Error("update-pod handler: unexpected object type", "new object", newObj)
				return
			}
			log.Debug(
				"update-pod handler called",
				"pod-name", newPod.Name,
				"pod-namespace", newPod.Namespace,
				"pod-uid", string(newPod.UID),
			)
			r.updatePod(oldPod, newPod)
		},
		DeleteFunc: func(obj interface{}) {
			// Remove all containers for this pod
			pod, ok := obj.(*corev1.Pod)
			if !ok {
				log.Error("delete-pod handler: unexpected object type", "object", obj)
				return
			}
			log.Debug(
				"delete-pod handler called",
				"pod-name", pod.Name,
				"pod-namespace", pod.Namespace,
				"pod-uid", string(pod.UID),
			)
			r.deletePod(pod)
		},
	}
}
