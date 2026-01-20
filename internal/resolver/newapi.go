package resolver

func (r *Resolver) AddPod2(pod *PodData) {
	r.mu.Lock()
	defer r.mu.Unlock()

	// We are in a create, we should not have the pod already in the cache
	if _, ok := r.podCache[pod.UID]; ok {
		r.logger.Error(
			"add-pod: pod already exists in podCache",
			"pod-name", pod.Name,
			"pod-namespace", pod.Namespace,
			"pod-uid", string(pod.UID),
		)
		return
	}

	r.podCache[state.podUID()] = state

	r.podContainersResolveCgroups(state)

	// Now ideally we should have all cgroup IDs resolved, so we can populate the policy map
	if err := r.applyPolicyToPodIfPresent(state); err != nil {
		r.logger.Error("failed to apply policy to pod",
			"error", err,
		)
	}
}
