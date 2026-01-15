|              |                                 |
| :----------- | :------------------------------ |
| Feature Name | OCI hooks                       |
| Start Date   | Jan. 05, 2026                   |
| Category     | enforcement                     |
| RFC PR       | [fill this in after opening PR] |
| State        | **ACCEPTED**                    |

# Summary

[summary]: #summary

<!---
Brief (one-paragraph) explanation of the feature.
--->

This RFC covers options that we inject into container's lifecycle to make sure a policy can take effect before any unauthorized commands runs.

# Motivation

[motivation]: #motivation

In the current design, the policy engine depends on [a pod informer](https://github.com/neuvector/runtime-enforcer/blob/b592270bf92956c18b35c2ef5843ecb177014b8d/internal/resolver/resolver.go#L325) to assign a policy to pods.  When runtime enforcer daemon receives an event from API server, it checks its label and container name, finds the policy ID that it belongs to, and updates the related ebpf map.

However, the container creation flow and the pod informer are asynchronous.  Without a special handling, it's possible that we could not determine the policy of the container in a timely fashion before the pod performs unallowed actions.

## Examples / User Stories

[examples]: #examples

As a user, I'd like all of my workloads to be protected by my policies, including the entry points of containers and short-lived pods.

# Detailed design

[design]: #detailed-design


In order to assign a policy to a pod before it performs unauthorized commands, we have to inject into the container's lifecycle and make sure that the policy is taking effect before a container starts.

[NRI](https://github.com/containerd/nri) provides a way to inject into how a pod and its containers are created.  In addition to receiving notification via hook like `StartContainer`, we can also inject extra data into container's runtime spec (Container Adjustment).

NRI is available since v1.7.0 and enabled by default on recent containerd since [v2.0](https://github.com/containerd/containerd/pull/9744).  CRIO also enabled it by default since [v1.30](https://github.com/cri-o/cri-o/pull/7790). 

## Flow

To assign a policy to a container, we follow these steps:

1. Register a NRI plugin that supports `StartContainer`. 
2. In NRI `StartContainer` hook, we evaluate the policy using Labels from [api.PodSandbox](https://github.com/containerd/nri/blob/009475630ff7946572d57c0ce42fe2885f60d86b/pkg/api/api.pb.go#L1875) and [api.Container](https://github.com/containerd/nri/blob/009475630ff7946572d57c0ce42fe2885f60d86b/pkg/api/api.pb.go#L2081).  
3. At this point, the container's cgroup is already created.  We can retrieve the cgroup ID by parsing the path specified in [api.Container.Linux.CgroupsPath](https://github.com/containerd/nri/blob/009475630ff7946572d57c0ce42fe2885f60d86b/pkg/api/api.pb.go#L2523C2-L2523C13).  Then, we simply follow the same logic with the normal container path to update ebpf map to assign a policy to a new container.

## Event Enrichment

While NRI can help to setup policy before a container starts, its information regarding a pod and its containers is limited and doesn't have many fields defined in a kubernetes pod spec, e.g., ownerReferences that we use to construct workload name and workload kind.  Besides, NRI has a limited window to respond to container runtime.  It's ideal that we rely on other mechanism to enrich events, e.g., the existing informer, instead of using NRI for these events. 

## Timeout and fail scenario

The default behavior of NRI is fail-open.  The NRI hook should already give us enough time to assign a policy to a container given that we don't rely on extra component to make the policy decision.  In the unlikely event where it needs extra time, the timeout value can be adjusted on [the container runtime side](https://github.com/containerd/containerd/blob/main/docs/NRI.md).

# Drawbacks

[drawbacks]: #drawbacks

# Alternatives

[alternatives]: #alternatives

## OCI hook + NRI hook.

It's a known approach that we can implement an executable, copy the executable into the host, and inject it into the hooks field of [opencontainers runtime spec](https://github.com/opencontainers/runtime-spec/blob/main/runtime.md), e.g., `CreateRuntime`, through NRI hook.  Then, the low level runtime, e.g., runc, will trigger the hooks based on the stage of a container's lifecycle.

The biggest advantage of this approach is that, it provides the flexibility for platforms that don't have NRI support.  In that case, users are supposed to be able to inject OCI hooks by modifying their container runtime setup.  However, this usage comes with limited support and is not well documented.

Besides, there is other drawback:

- Not all platforms allow host files to be changed.  For example, [Google's container-optimized OS always mounts its host volume as readonly](https://docs.cloud.google.com/container-optimized-os/docs/concepts/security#immutable_root_filesystem_and_verified_boot).
- It needs extra care in order to upgrade the OCI hook executable.  This would also conflict with https://github.com/neuvector/runtime-enforcer/issues/96 due to potential two versions of OCI hooks running.

Based on these, this is not considered as the approach that we'd like proceed with first.

## Other NRI hook points

In addition to `StartContainer` NRI hook, `CreateContainer` and `UpdateContainer` NRI hooks are both considered.

### CreateContainer

When this hook runs, the cgroup of the target container is not created yet.  While this issue is technically possible to overcome, it requires more handling by comparing cgroup path.  When doing this, we would lose `kind` support and potentially kernels prior to 5.11 due to the max key size of ebpf hash maps.

### UpdateContainer

`UpdateContainer` is not called by kubelet, so it's not useful for us to get the up-to-date information from k8s.  A kubernetes informer is still needed to retrieve related pod metadata and change policy assignment.

# Unresolved questions

[unresolved]: #unresolved-questions

<!---
- What are the unknowns?
- What can happen if Murphy's law holds true?
--->
