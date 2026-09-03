|              |                                                        |
| :----------- | :----------------------------------------------------- |
| Feature Name | CRD revisit and user workflow                          |
| Start Date   | 20 Nov 2025                                            |
| Category     | CRDs                                                   |
| RFC PR       | https://github.com/kubewarden/runtime-enforcer/pull/45 |
| State        | **ACCEPTED**                                           |

# Summary

[summary]: #summary

This RFC tries to summarize the disccusion happened to far about the policy lifecycle, and tries to also stabilize CRDs in terms of lifecycle, names, and possible interactions.

This RFC supersedes [RFC-001](https://github.com/kubewarden/runtime-enforcer/blob/main/docs/rfc/0001-workloadgroup.md).

# Motivation

[motivation]: #motivation

Before implementing a runtime enforcement workflow, in this post-POC phase we want to reach consensus on two topics:

- Kubernetes' CRD names and specifications
- The user journey and workflow, especially when not by a UI of some sort

## Examples / User Stories

[examples]: #examples

The following user stories are to be intended as examples:

- As a user I want to configure a security policy for a given workload
- As a user I want the processes that run into my workloads to be learned automatically and be proposed to me
- As a user I want to inherit the security policy for my workload from a pre-existing template
- As a user I want to promote a policy proposal to an actual deployed security policy

# Detailed design

[design]: #detailed-design

## CRDs Overview
This is a quick overview of all the CRDs we’re going to define. Each one of them is going to be described in depth in the next sections.

| CRD Current Name               | CRD New Name           | Description                                                                                                        |
| ------------------------------ | ---------------------- | ------------------------------------------------------------------------------------------------------------------ |
| WorkloadSecurityPolicyProposal | WorkloadPolicyProposal | Proposed policies learned from workload behavior. Now includes per-container rules.                                |
| WorkloadSecurityPolicy         | WorkloadPolicy         | Defines the enforcement policy (monitor/protect) for a workload, grouping per-container rules or image references. |
| ClusterWorkloadSecurityPolicy  | (Removed)              | Replaced by ImagePolicy for cluster-wide reusable profiles.                                                        |
| (New)                          | ImagePolicy            | Defines reusable runtime rules (templates) based on container image, used for policy templating.                   |
| (New)                          | ContainerPolicy        | Defines rules that will be used to handle sidecar containers at a cluster level.                                   |

Changes from the previous version:
- The WorkloadSecurityPolicy was renamed into `WorkloadPolicy`
- We have new CRDs for the `ImagePolicy` and the `ContainerPolicy`
- The `ClusterWorkloadSecurityPolicy` has been removed

## Learning Phase

During learning mode, we create WorkloadPolicyProposal resources. These resources are structured in this way:

```yaml
apiVersion: security.rancher.io/v1alpha1
kind: WorkloadPolicyProposal
metadata:
  name: statefulsets-pgsql # <workload_type>-<workload_name>
  ownerReferences:
  - apiVersion: v1
    kind: StatefulSet
    name: pgsql
    uid: 39a32022-4c8f-424e-a8b6-3c92af3acb2e
spec:
  rulesByContainer:
    "db-migration": # rules applied to the container named "db-migration"
       executables:
         allowed:
           - /bin/bash
           - /usr/bin/psql
    "postgres": # rules applied to the container named "postgres"
       executables:
         allowed:
           - /usr/bin/psql
    "otel-collector": # rules applied to the container named "otel-collector"
       executables:
         allowed:
           - /usr/bin/otel-collector
```

Changes compared to the current implementation:
- The rules section has been replaced by rulesByContainer. This new field holds a map with the name of the containers as key, and the list of the container rules as value.
- The `selector` field has been removed from the CRD. 

Notes on the behavior:

- The WorkloadPolicyProposal has an `ownerReference` that ties it back to the workload resource for which the behaviour was observed.
- When the observed workload is deleted, the associated WorkloadPolicyProposal is deleted as well.
- When we switch from a `WorkloadPolicyProposal` to an actual `WorkloadPolicy` we delete the `WorkloadPolicyProposal` and don’t recreate it again
- In case of workload rollout, the WorkloadPolicyProposal continues to learn like nothing happened. 

## The WorkloadPolicy resource
Policies are defined using the WorkloadPolicy resource. This is how this resource looks:

```yaml
apiVersion: security.rancher.io/v1alpha1
kind: WorkloadPolicy
metadata:
  name: statefulsets-pgsql
  namespace: default
spec:
  mode: monitor # monitor | protect
  rulesByContainer:
    postgres:
      rules:
        executables:
          allowed:
            - /usr/bin/psql
    otel-collector: 
      rules:
        executables:
          allowed:
            - /usr/bin/otel-collector
    db-migration:
      rules:
        executables:
          allowed:
            - /bin/bash
            - /usr/bin/psql
```

Changes compared to the current implementation:

- The rules section has been replaced by `rulesByContainer`. This new field holds a map with the name of the containers as key, and the list of the container rules as value.
- The `WorkloadPolicy` does not have the label selector field to identify the pods to protect.

Notes on the behavior:

- When the enforced workload is deleted, the WorkloadPolicy is still alive; it should be deleted manually
- When a `WorkloadPolicy` is deleted, we will implement a mutating admission controller that will prevent users to delete such a policy if it is referenced by any workload/pod
- In case of workload rollout, the WorkloadPolicy remains unchanged. If it causes issues with the rollout, the user is in charge of rolling back to the previous version or destroying the policy

## Binding a WorkloadPolicy
A workload is protected by a WorkloadPolicy the usage of a unique label `security.rancher.io/policy: <policy-name>`.

Since the label is mandatory, we can rely on it to understand if a workload is covered by a policy or not.  A rollout could be required if the workload was initially created without the label.

## Using the ImagePolicy to inherit rules from pre-made templates

Pods are made by containers, each one of them running a container image. The same container image can be reused by multiple Pods, but its runtime behavior is mostly the same.

Most of the time, a Redis/Tomcat/NodeJS container image is always going to behave in the same way. There could be some exceptions, we must take that scenario into account.

Vendors already distribute maintained container images through their platforms. It would make sense to tie our profiles to the container images, rather than thinking about the concept of “workload”.

Let's define an ImagePolicy:

```yaml
apiVersion: security.rancher.io/v1alpha1
kind: ImagePolicy
metadata:
  name: otel-collector
spec:
  image: # optional - inspired by SBOMScanner's imageMetadata
    registry: "registry.suse.com"
    repository: "otel-collector"
    tag: "v1.0.0"
    digest: "sha256:1234567890"
  rules:
    executables:
      allowed:
        - /usr/bin/otel-collector
```

Then it can be consumed by a WorkloadPolicy in this way:

```yaml
apiVersion: security.rancher.io/v1alpha1
kind: WorkloadSecurityPolicy
metadata:
  name: postgres-policy
  namespace: default
spec:
  mode: monitor # monitor | protect
  rulesByContainer:
    postgres:
      rules:
        executables:
          allowed:
            - /usr/bin/psql
    otel-collector:
      rules:
        executables:
          imagePolicyRef: otel-collector # name of the ImagePolicy
    db-migration:
      rules:
        executables:
          allowed:
            - /bin/bash
            - /usr/bin/psql
```

When defining the rules of a container, the user can either define a list of explicit rules or can make a reference to an existing ImagePolicy by using the `imagePolicyRef` attribute. In its first implementation it will not be possible to define both `rules` and `imagePolicyRef` for the same container.

To avoid uncertainty we must:

- Introduce a ValidatingWebhook that ensures all the ImagePolicy objects referenced by WorkloadSecurityPolicy exist. The webhook would process CREATE and UPDATE events.
- Add a finalizer to each ImagePolicy, the deletion of an ImagePolicy resource must be allowed only when no WorkloadSecurityPolicy is referencing it.

ImagePolicy resources aren't namespaced; they are cluster-wide available resources that can be referenced by any other resource.

## Handling Violations in Monitor/Protect Mode

When a WorkloadPolicy is in monitor or protect mode, the runtime enforcer generates violation notifications (aka processes that are not on the allow list). The difference is that in monitor mode, the violations are still allowed, while in protect mode, they are blocked.

A notification is sent to the Security Hub in the form of an OpenTelemetry event.

In this version we are going to create a new CRD related to the tuning aspects of a WorkloadPolicy, that holds the violation data for the policy while the policy is set in **monitor** mode.

When the policy is in protect mode, the only way of getting a notification about attempted violations will be OpenTelemetry events.

At the moment, the idea is to use the tuning CRD in order to save space on the WorkloadPolicy one.

```yaml
apiVersion: security.rancher.io/v1alpha1
kind: WorkloadPolicyTuning
metadata:
  name: postgres-policy
  namespace: default
spec:
  # ...
status:
  violations:
    lastObservedTimestamp: "2025-11-14T17:40:00Z"
    totalViolations: 42
    latestEvents:
      - containerName: postgres
        executable: /usr/bin/wget
        timestamp: "2025-11-14T17:39:50Z"
      - containerName: db-migration
        executable: /bin/sh
        timestamp: "2025-11-14T17:39:55Z"
```

The design is not definitive, but the idea is:

- Users without the UI will simply update the tuning resource manually if they want to tolerate some violations
- The rancher extension will use this status to run a kubectl patch with the desired changes based on the user input.

An alternative design with a map of unique violations could be the following:

```yaml 
status:
  violations:
    lastObservedTimestamp: "2025-11-14T17:40:00Z"
    totalViolations: 42
    containerViolations:
      postgres:
        "/usr/bin/wget":
          count: 15
          lastObservedMode: protect
          lastObservedTimestamp: "2025-11-14T17:39:50Z"
        "/usr/local/bin/curl":
          count: 1
          lastObservedMode: monitor
          lastObservedTimestamp: "2025-11-14T17:40:00Z"      
      db-migration:
        "/bin/sh":
          count: 27
          lastObservedMode: monitor
          lastObservedTimestamp: "2025-11-14T17:39:55Z"
```

At this stage we don't want to commit on the name of the WorkloadPolicyTuning resource as we might come up with a better name later, and we will for sure revisit at least the naming of the resource. We decided to defer that to a dedicated RFC when we get to implement tuning for policies.

## Tetragon integration strategy

The current integration strategy between our policy CRDs and tetragon’s `TracingPolicyNamespaced` stays the same.

Let’s go through all the possible cases, considering the current architecture of Tetragon.

The user creates a `WorkloadSecurityPolicy` named `pgsql` inside of the infra namespace.

Our controller will examine the policy and, for each container rule it will create a tetragon `TracingPolicyNamespaced` inside of the infra namespace.

The tetragon policy will identify the containers by using two information:

- Identify the pod by using the `security.rancher.io/policy: <policy-name>` label. In this case, `security.rancher.io/policy:pgsql`.
- Identify the container by using the name of the container mentioned inside of the `.spec.rulesByContainer.[]`

Depending on the mode of the WorkloadPolicy, we will reconcile a different type of tetragon policy, like we’re currently doing. At this point, the job or our controller is done.

The Tetragon policy will stay “dormant” until a user assigns the special `security.rancher.io/policy: <policy-name>` to their workload.

We’re currently discussing with Tetragon maintainers to revisit how policies can be defined, to make them more “workload centric”. The work with upstream began before we did this refinement of our CRDs. Nevertheless, the proposal we made upstream remains valid also with this new set of CRDs and workflow.

## Transitions

These are the transitions that a policy will go through:

- Learn -> Monitor: given a `WorkloadPolicyProposal` that correctly learned a workload's behavior, the user applies a label to mark it as ready to be deployed. The `WorkloadPolicyProposal` gets deleted and a `WorkloadPolicy` with the corresponding behavior and the mode set to `monitor` gets created.
- Monitor -> Protect: given a `WorkloadPolicy` with `mode: monitor`, the user just modifies the resource setting `monitor: protect`.
- Protect -> Monitor: given a `WorkloadPolicy` with `mode: protect`, the user just modifies the resource setting `mode: monitor`.
- Protect -> Learn: given a `WorkloadPolicy` with `mode: protect`, it will be sufficient to delete it. Subsequently, a `WorkloadPolicyProposal` will be created from scratch.

# Drawbacks

[drawbacks]: #drawbacks

We didn't observe any particular drawback in the workflow. Anyway, there are considerations to make:

- Having rules specified by container will allow us for more granularity and will allow us to support more scenarios (init-containers, sidecars), on the other hand it will have a performance impact that we'll have to measure and document.

# Alternatives

[alternatives]: #alternatives

We considered a bunch of alternatives. For example putting the ImagePolicy and the WorkloadPolicy together:

```yaml
apiVersion: security.rancher.io/v1alpha1
kind: WorkloadSecurityPolicy
metadata:
  name: database
spec:
  mode: monitor # monitor/protect
  selector:
    matchLabels:
      app: postgres
  policies:
    # ImagePolicy profile to apply to the the container named "db-migration"
    "db-migration": psql-init
    "postgres": psql
    "otel-collector": otel-sidecar
```

But it didn't work out because this way it becomes very hard to achieve the granularity we wanted, even for a first POC that could resist to time.

We also tried experimenting with applying annotations to pods referencing directly the ImagePolicy, but didn't lead us to any good-enough conclusion.

# Unresolved questions

[unresolved]: #unresolved-questions

- How do we name the policy tuning CRD?

