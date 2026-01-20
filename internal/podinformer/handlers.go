package podinformer

import (
	"log/slog"

	"github.com/neuvector/runtime-enforcer/internal/resolver"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/tools/cache"
)

// PodEventHandlers returns the event handlers for pod events.
func PodEventHandlers(logger *slog.Logger, r *resolver.Resolver) cache.ResourceEventHandler {
	return cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			pod, ok := obj.(*corev1.Pod)
			if !ok {
				logger.Error("add-pod handler: unexpected object type", "object", obj)
				return
			}
			logger.Debug(
				"add-pod handler called",
				"pod-name", pod.Name,
				"pod-namespace", pod.Namespace,
				"pod-uid", string(pod.UID),
			)

			r.AddPod(pod)
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			oldPod, ok := oldObj.(*corev1.Pod)
			if !ok {
				logger.Error("update-pod handler: unexpected object type", "old object", oldObj)
				return
			}
			newPod, ok := newObj.(*corev1.Pod)
			if !ok {
				logger.Error("update-pod handler: unexpected object type", "new object", newObj)
				return
			}
			logger.Debug(
				"update-pod handler called",
				"pod-name", newPod.Name,
				"pod-namespace", newPod.Namespace,
				"pod-uid", string(newPod.UID),
			)
			r.UpdatePod(oldPod, newPod)
		},
		DeleteFunc: func(obj interface{}) {
			// Remove all containers for this pod
			pod, ok := obj.(*corev1.Pod)
			if !ok {
				logger.Error("delete-pod handler: unexpected object type", "object", obj)
				return
			}
			logger.Debug(
				"delete-pod handler called",
				"pod-name", pod.Name,
				"pod-namespace", pod.Namespace,
				"pod-uid", string(pod.UID),
			)
			r.DeletePod(pod)
		},
	}
}
