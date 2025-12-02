package resolver

import (
	"context"
	"log/slog"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/tools/cache"

	cmCache "sigs.k8s.io/controller-runtime/pkg/cache"
)

type CgroupID = uint64
type ContainerID = string
type PodID = string
type ContainerName = string

type containerInfo struct {
	podID PodID
	name  ContainerName
}

type Resolver struct {
	logger *slog.Logger
	// todo!: we should add a cache with deleted pods/containers so that we can resolve also recently deleted ones
	podCache          map[PodID]*podInfo
	cgroupToContainer map[CgroupID]ContainerID // cgroupID to containerID
	containerCache    map[ContainerID]containerInfo
	// this is the callback to update the bpm map
	updateFunc func(pod *corev1.Pod) []string

	criResolver *criResolver
}

func (r *Resolver) EventHandler() cache.ResourceEventHandler {
	return cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			pod, ok := obj.(*corev1.Pod)
			if !ok {
				r.logger.Error("add-pod handler: unexpected object type", "object", obj)
				return
			}
			r.logger.Debug("add-pod handler called", "pod", pod)

			info, ok := r.podCache[PodID(pod.UID)]
			if ok {
				r.logger.Error("add-pod handler: pod already exists in podCache", "old pod", info, "new pod", pod)
				return
			}

			// We store the entry into the cache
			// We always overwrite the container info, since the rthook cannot give us information on the workload
			r.podCache[PodID(pod.UID)] = getPodInfo(pod)

			// We resolve the pod containersID
			containerIDs := podContainersIDs(pod)
			for cID, cName := range containerIDs {
				r.containerCache[cID] = containerInfo{
					podID: PodID(pod.UID),
					name:  cName,
				}

				// We do the resolution in a synchronous way
				cgID, err := r.criResolver.resolverCgroupID(cID)
				if err != nil {
					r.logger.Error("failed to resolve cgroup ID", "containerID", cID, "error", err)
					continue
				}
				r.cgroupToContainer[CgroupID(cgID)] = cID
			}
		},
		UpdateFunc: func(_, newObj interface{}) {
			pod, ok := newObj.(*corev1.Pod)
			if !ok {
				r.logger.Error("update-pod handler: unexpected object type", "object", newObj)
				return
			}
			r.logger.Debug("update-pod handler called", "pod", pod)

			_, ok = r.podCache[PodID(pod.UID)]
			if !ok {
				r.logger.Error("update-pod handler: pod does not exist in podCache", "pod", pod)
				// we add it and we continue
				r.podCache[PodID(pod.UID)] = getPodInfo(pod)
			}

			// not sure if it makes sense to update the pod info in any case, for now we skip it

			// We need to get all container IDs again so that we can update them if something is changed.
			// If the pod is in crashloop backoff, its containers will be restarted with new containerIDs/cgroupIDs
			containerIDs := podContainersIDs(pod)
			for cID, cName := range containerIDs {
				_, exists := r.containerCache[cID]
				if !exists {
					r.containerCache[cID] = containerInfo{
						podID: PodID(pod.UID),
						name:  cName,
					}
				}
				// for now we ask the resolution again in any case, we can optimize later if needed
				r.criResolver.resolverCgroupID(cID)
			}
		},
		DeleteFunc: func(obj interface{}) {
			var pod *corev1.Pod
			switch concreteObj := obj.(type) {
			case *corev1.Pod:
				pod = concreteObj
			case cache.DeletedFinalStateUnknown:
				// Handle the case when the watcher missed the deletion event
				// (e.g. due to a lost apiserver connection).
				deletedObj, ok := concreteObj.Obj.(*corev1.Pod)
				if !ok {
					r.logger.Error("delete-pod handler: missed delete event is not a pod", "object", concreteObj.Obj)
					return
				}
				pod = deletedObj
			default:
				r.logger.Error("delete-pod handler: delete event is not a pod", "object", obj)
				return
			}

			// todo!: we need to store deleted pods in a separate cache with LRU eviction so that we can resolve recently deleted containers
			// todo!: nobody is deleting the cgroupToContainer entries for the containers of this pod!

			delete(r.podCache, PodID(pod.UID))

			// We also need to delete the container info
			for cID := range podContainersIDs(pod) {
				delete(r.containerCache, cID)
			}
		},
	}
}

func NewResolver(ctx context.Context, logger *slog.Logger, informer cmCache.Informer) (*Resolver, error) {
	var err error
	r := &Resolver{
		logger:            logger.With("component", "resolver"),
		podCache:          make(map[PodID]*podInfo),
		cgroupToContainer: make(map[CgroupID]ContainerID),
		containerCache:    make(map[ContainerID]containerInfo),
	}

	r.criResolver, err = newCRIResolver(ctx, r.logger)
	if err != nil {
		return nil, err
	}

	informer.AddEventHandler(r.EventHandler())
	// todo!: add handlers for the rthook
	// todo!: we can do a first scan of all existing containers to populate the cache initially
	return r, nil
}

func (r *Resolver) Start(ctx context.Context) error {
	r.logger.InfoContext(ctx, "Resolver started")

	for {
		select {
		case <-ctx.Done():
			return nil

		}
	}
}
