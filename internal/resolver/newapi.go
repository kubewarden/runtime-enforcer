package resolver

func (r *Resolver) AddPod(state *PodState) {
	r.mu.Lock()
	defer r.mu.Unlock()

	// We are in a create we should not have the pod already in the cache
	if oldState, ok := r.podCache[state.podUid()]; ok {
		r.logger.Error(
			"add-pod: pod already exists in podCache",
			"old pod info", oldState.info,
			"new pod-name", state.podName(),
			"new pod-namespace", state.podNameSpace(),
			"pod-uid", string(state.podUid()),
		)
		return
	}
	r.podCache[state.podUid()] = state

	// TODO!:

	r.podContainersResolveCgroups(state)

	// Now ideally we should have all cgroup IDs resolved, so we can populate the policy map
	r.applyPoliciesToPod(state)
}

func (r *Resolver) UpdatePod(state *PodState) {

}

func (r *Resolver) UpdatePod(state *PodState) {

}
