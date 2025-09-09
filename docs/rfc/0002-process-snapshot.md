|              |                                                           |
| :----------- | :-------------------------------------------------------- |
| Feature Name | Generate Process Snapshot using Tetragon                  |
| Start Date   | Sep. 9, 2025                                              |
| Category     | Learner                                                   |
| RFC PR       | https://github.com/neuvector/runtime-enforcement/pull/193 |
| State        | **ACCEPTED**                                              |

# Summary

[summary]: #summary

<!---
Brief (one-paragraph) explanation of the feature.
--->

This RFC discusses how we generate a process snapshot of a node in our per-node component(daemon).

# Motivation

[motivation]: #motivation

<!---
- Why are we doing this?
- What use cases does it support?
- What is the expected outcome?

Describe the problem you are trying to solve, and its constraints, without
coupling them too closely to the solution you have in mind. If this RFC is not
accepted, the motivation can be used to develop alternative solutions.
--->

A process snapshot represents the current state of a protected environment, which includes PIDs, executable paths and their container metadata.

Although we can build the whole container profiles using only process events emitted by Tetragon, it takes time until all behavior is learned.

A process snapshot would provide what we need in order to address this issue.

There are several options to generate a process snapshot.  This RFC is written to document these options and ensures that we have consensus in team.

## Examples / User Stories

[examples]: #examples

As a system admin, I'd like to learn container behavior without the need to restart my workload, for example, the hardened container with only the entrypoint executable.

# Detailed design

[design]: #detailed-design

Instead of requiring `hostPID: true`, container runtime socket access, and other permissions, we rely on Tetragon's `FineGuidanceSensors` service and its `GetDebug` gRPC API. 

`GetDebug` API returns all process information and their container metadata that have been cached inside Tetragon.  With this, we can construct the process snapshot and trigger the behavior learning flow.

# Drawbacks

[drawbacks]: #drawbacks

Without a process snapshot, for those containers with only one executable, we will not learn their behavior until the container restarts.

Note: Even with the process snapshot, we can't still catch behavior from an init container and the behavior when a container is starting.  This is the limitation. 

# Alternatives

[alternatives]: #alternatives

## Implement everything on our own

Many security softwares already do this, including neuvector.  The flow is basically,

1. Get all running process information using `hostPID: true` and root permission.
2. Read each running process's `/proc/<pid>/cgroup` and find out its container ID.
3. Query its container runtime's socket with the container ID and retrieve the process' container metadata.

Although it's technically possible to implement everything again, this does come with a few drawback:

- Extra privilege requirement and attack surface
  - Having `hostPID: true` and root permission allows our component to read environment variables of all processes in the system, which is an attack surface for sensitive information.
  - The ability to access container runtime socket is another attack surface for running unauthorized workload.
- Bigger test scope.
  - There is no formal guideline to determine the container ID via `/proc/<pid>/cgroup`.  It's all by convention.
  - The test scope would include different high-level container runtimes (docker, containerd, or crio), low-level runtime (runc, crun or gvisor) and kubernetes flavors (k8s, OpenShift, k3s, kind, and more...)
- Inconsistent behavior with Tetragon.
  - Because Tetragon does exactly the same thing, it makes it difficult to match Tetragon's behavior for each release.

## Get Process Snapshot using tetragon.log

While the `GetDebug` API is used by the tetra CLI and is therefore considered stable enough, `GetDebug` is a debug API, so it may be subject to change if upstream maintainers decide to change it.

If this happens, we can move to `tetragon.log`.

Tetragon takes a snapshot of processes too while building its own process cache during startup.  A few `PROCESS_EXEC` events with `procFS` flag set will be generated and left under `/var/run/cilium/tetragon/tetragon.log` in the host, so it's an alternative when `GetDebug()` API becomes not ideal.   More information can be found here: https://tetragon.io/docs/reference/grpc-api/#process

# Unresolved questions

[unresolved]: #unresolved-questions


<!---
- What are the unknowns?
- What can happen if Murphy's law holds true?
--->


