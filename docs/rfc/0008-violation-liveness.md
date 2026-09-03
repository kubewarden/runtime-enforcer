|              |                                                         |
| :----------- | :------------------------------------------------------ |
| Feature Name | Violation Liveness and Resolution Tracking              |
| Start Date   | 2026-06-10                                              |
| Category     | Security / Observability                                |
| RFC PR       | https://github.com/kubewarden/runtime-enforcer/pull/678 |
| State        | **ACCEPTED**                                            |

# Summary

[summary]: #summary

Right now violations are a flat historical log: once recorded they stay in
`status.violations` until the 100-record cap pushes them out. There is no way
to tell which ones still represent an active risk and which have already been
resolved by an allowlist update or a workload redeployment, and operators lack
context about which workload produced each violation. We enrich violation
records with workload metadata, support punctual violation acknowledgements
via a controller-consumed policy annotation, and delete expired entries when
building the violations list. This gives operators meaningful context and a
clean way to acknowledge known issues while automatically removing resolved
ones.

# Motivation

[motivation]: #motivation

Without liveness, every violation looks equally urgent. A security engineer
triaging a policy with 40 violations has no way to know that 35 of them came
from pods that were redeployed last week, or that 3 more refer to binaries
that have since been allowlisted. Dashboards, alerts, and compliance reports
all end up noisier than they need to be, and there is no clean signal for
"is this workload currently clean?"

## Examples

[examples]: #examples

**Executable added to the allowlist.** A violation for `/usr/local/bin/debug-tool`
sits in the violations list. The operator edits the policy and adds the
path under `spec.rulesByContainer["app"].executables.allowed`. On the next
reconcile the controller sees the match and deletes the record from the list.

**Violation acknowledged.** An operator notices a violation for
`/opt/scripts/cleanup.sh` and knows it is part of an ongoing incident. They
read the violation's `id` from `status.violations` (e.g. via
`kubectl describe workloadpolicy`) and patch the policy with an annotation
referencing it:

```yaml
metadata:
  annotations:
    runtime-enforcer.security.rancher.io/acknowledge/42: "ongoing incident, see JIRA-1234"
```

On the next reconcile the controller:

1. Finds the annotation, extracts the violation `id` and `reason`.
2. Looks up the matching record in `status.violations` and removes it.
3. Appends it to `status.acknowledgedViolations` (carrying the original
   record, the reason, and the acknowledgement timestamp).
4. Emits an OTEL log with the violation data and the reason.
5. Removes the annotation from the policy.

After this, `status.violations` only contains items that actually need
attention, and `status.acknowledgedViolations` is the audit trail of
explicitly triaged ones.

**Mixed state.** After a few days, only unresolved violations remain in the
list:

```
status.violations:
  /usr/bin/nc                 (still running, not allowed, still in list)

status.acknowledgedViolations:
  /opt/scripts/cleanup.sh     (acknowledged via annotation, moved here)
```

The violations list now contains only items that actually need attention.

# Detailed design

[design]: #detailed-design

## Violation record enrichment

Each `ViolationRecord` gains a stable `id` plus workload fields
(`workloadName`, `workloadKind`) alongside the existing `podName`. The
`id` makes a single violation addressable from outside the controller; the
workload fields give operators immediate context about which workload
produced the violation. Workload metadata is populated from the pod's owner
references when the violation is recorded.

The agent's in-memory dedup key (policy, pod, container, executable, action)
is reused by the controller to recognise that a violation scraped from the
agent on a later tick is the same one it already knows about, so the `id`
(and workload fields) are preserved across scrapes.

## Violation `id` as an evergrowing integer

The `id` is a per-policy, monotonically increasing `uint64` assigned by the
controller when the record is first added to the status. It is not a UUID
and not globally unique: it is unique within the policy's violation stream
and is meant to be a short, human-readable reference ("see violation 42 of
policy foo/bar"). Ids are never reused, even after a record is
acknowledged or removed by the allowlist-expiration pass, so they remain
stable references for OTEL logs, audit trails, and operator
back-and-forth.

The counter lives on the policy itself as `status.nextViolationID`. The
controller allocates the next id by reading the current value, writing it
into the new `ViolationRecord.id`, and bumping `status.nextViolationID` by
one. On the first reconcile of a fresh policy the field defaults to `1`.
On upgrade, existing policies with no `nextViolationID` are initialized
to `max(existingIds) + 1` (or `1` if the list is empty) on the next
reconcile that adds a new record. We accept that pre-upgrade records
without an `id` are not addressable, mirroring the existing decision not
to backfill workload fields.

Using an integer keeps annotation keys short and the wire format
opaque-free ("`/acknowledge/42`" is much friendlier than a UUID) at the
cost of the controller having to coordinate the counter through the
status field. Because status writes go through the API server's
optimistic-concurrency loop, a double-allocation cannot happen: the
controller reads the current counter, allocates an id, and writes the
status with the bumped counter in a single update, retrying on
conflict.

## Acknowledgement via annotation

Operators acknowledge a specific violation by setting an annotation on the
`WorkloadPolicy` with the form:

```
<annotation-prefix>/<violation-id>: "<reason>"
```

The default annotation prefix is
`runtime-enforcer.security.rancher.io/acknowledge`. The key's suffix is
the `id` of the violation being acknowledged, taken from
`status.violations[].id`. The value is a free-form human-readable reason
recorded into `status.acknowledgedViolations`.

Example:

```yaml
metadata:
  annotations:
    runtime-enforcer.security.rancher.io/acknowledge/42: "ongoing incident, see JIRA-1234"
```

On every reconcile the controller:

1. Collects all annotations on the policy whose key has the acknowledgement
   prefix.
2. For each such annotation, parses the violation `id` from the key and the
   `reason` from the value.
3. Looks up the record in `status.violations` by `id`. If found:
   - Removes it from `status.violations`.
   - Appends a new entry to `status.acknowledgedViolations` carrying the
     full original `ViolationRecord`, the `reason`, and the
     acknowledgement timestamp.
   - Emits an OTEL log record with `event_name=policy_violation_acknowledged`
     containing the violation data and the reason (see OTEL logging below).
   - Records the annotation key in a "to-be-removed" set.
4. If the `id` does not match any current violation, the annotation is
   treated as a no-op (still removed), and a warning OTEL log is emitted
   so the operator can tell their annotation was stale.
5. After processing all acknowledgement annotations, the controller removes
   them from the policy object via a patch. Acknowledgements are
   one-shot: once consumed, the annotation is gone and the acknowledgement
   lives on in `status.acknowledgedViolations`.

The acknowledgement is "punctual" in the sense that it targets one specific
violation by `id` and disappears after being processed. It does not affect
future violations of the same executable, so a reappearing violation will
have to be acknowledged again.

## Resolved violations via allowlist update

When the operator edits the policy and adds an executable to
`spec.rulesByContainer[<container>].executables.allowed`, the controller
walks `status.violations` and deletes every record whose `executablePath`
is now allowed for its `containerName`. This is independent of the
acknowledgement flow above and does not produce an
`acknowledgedViolations` entry: resolved-by-allowlist is not a triage
decision, it is an actual remediation, and the audit trail for that is the
allowlist itself.

## Status layout

```go
type ViolationRecord struct {
    ID             uint64       `json:"id"`
    Timestamp      metav1.Time `json:"timestamp"`
    PodName        string      `json:"podName"`
    ContainerName  string      `json:"containerName"`
    ExecutablePath string      `json:"executablePath"`
    NodeName       string      `json:"nodeName"`
    Action         string      `json:"action"`
    WorkloadName   string      `json:"workloadName,omitempty"`
    WorkloadKind   string      `json:"workloadKind,omitempty"`
}

type AcknowledgedViolation struct {
    Violation      ViolationRecord `json:"violation"`
    Reason         string          `json:"reason"`
    AcknowledgedAt metav1.Time     `json:"acknowledgedAt"`
}

type WorkloadPolicyStatus struct {
    // ... existing fields ...
    Violations              []ViolationRecord         `json:"violations,omitempty"`
    AcknowledgedViolations  []AcknowledgedViolation   `json:"acknowledgedViolations,omitempty"`
    ActiveViolationCount    int                       `json:"activeViolationCount,omitempty"`
    NextViolationID         uint64                      `json:"nextViolationID,omitempty"`
}
```

`activeViolationCount` is derived from `len(status.violations)` and is the
field dashboards and alerts should consume. `acknowledgedViolations` is the
audit trail of explicit triage decisions; it is capped at
`MaxViolationRecords` (100) entries, the same cap that applies to
`status.violations`, and trims oldest-first once the cap is reached. It is
read-only from the operator's point of view. Operators who need a longer
triage history should rely on the OTEL acknowledgement log stream, which
is not bounded by the status cap.

## OTEL logging on acknowledgement

The controller reuses the OTEL log pipeline already used for violation
events (see RFC 0006). When an annotation is reconciled the controller
emits a structured log record with:

- `event_name = policy_violation_acknowledged`
- Attributes: the full `ViolationRecord` fields (id as integer, timestamp,
  pod, container, executable, node, action, workload), the `reason`, the
  policy's `namespace/name`, and the acknowledgement timestamp.
- Severity: `INFO` on success, `WARN` on stale `id`.

This gives operators a single OTEL stream that covers both the original
violation event and its acknowledgement, suitable for forwarding to a
SIEM. The acknowledgement record is emitted once, at reconcile time,
and is not re-emitted on subsequent reconciles.

## Active violations as a Prometheus metric

In addition to the per-event log stream, the controller exposes the
active violations count of each `WorkloadPolicy` as a Prometheus-
compatible counter via the existing OTEL collector pipeline (see RFC
0006). The metric, named `runtime_enforcer_active_violations`, carries
`policy_name` and `k8s_namespace_name` as labels and is refreshed on
every reconcile from `status.activeViolationCount` of the corresponding
policy. It complements the per-event `runtime_enforcer_violations_total`
counter already defined in RFC 0006, which counts every emitted
violation event regardless of whether it is still active: dashboards
and alerts can use the new metric for "how many unresolved violations
does this policy have right now" without having to scrape or parse
`WorkloadPolicy` status objects, while the existing per-event counter
keeps working as the audit trail of total observed violations.

## Why annotations and not spec / status

We considered putting acknowledgements in `spec.acknowledgedViolations`
(rejected, see alternatives). The annotation form is attractive because:

- **One-shot semantics**: the controller consumes the annotation by
  removing it, so the operator cannot accidentally re-trigger an
  acknowledgement or wonder whether it has been processed yet. The
  `status.acknowledgedViolations` list is the durable record.
- **No spec churn**: an acknowledgement is not a policy decision and
  should not affect `observedGeneration` or trigger a rollout. By
  living in metadata it does not bump the generation.
- **No new RBAC**: applying an annotation to a `WorkloadPolicy` only
  requires the `update` permission on the resource, which the operator
  already has.

## `kubectl runtime-enforcer policy ack`

The annotation is the wire format, but hand-editing a `WorkloadPolicy`
manifest to add an annotation is not a great UX. We add a new subcommand
to the existing `kubectl runtime-enforcer policy` plugin:

```
kubectl runtime-enforcer policy ack POLICY_NAME <violation-id> [--reason "..."] [flags]
```

Behavior:

- Resolves the policy in the current namespace (or `-n/--namespace`).
- Validates that `<violation-id>` exists in `status.violations` of the
  current revision of the policy. If it does not, the command fails
  fast with a clear error message (so the operator gets immediate
  feedback rather than a silent no-op reconcile).
- Patches the policy metadata to add the acknowledgement annotation
  with the resolved `<reason>` (prompted interactively if not passed
  via `--reason`).
- Supports `--dry-run` to print the patched object without sending it
  to the API server, matching the existing `allow`/`deny` subcommands.
- Supports shell completion for `<violation-id>` from
  `status.violations[].id` of the target policy, similar to how the
  `allow` subcommand completes from the violations list.

The subcommand is a thin wrapper: it does not know or care how the
controller reconciles the annotation, it only writes the annotation. The
controller is still the single source of truth for the
`acknowledgedViolations` list and the OTEL log. This keeps the
annotation-based design layered cleanly: the controller speaks
annotations, the plugin speaks operator UX, the two are kept in sync by
the annotation contract.

## RBAC and upgrade

The agent and gRPC proto will pass the workload provenance data to the
controller. The controller needs `update`/`patch` on `workloadpolicies` to
remove the acknowledgement annotations, which it already has (it writes status
today).

This design prioritises clarity over history preservation: resolved
violations disappear from `status.violations` rather than accumulating
with status markers. The allowlist and the `acknowledgedViolations`
list in `status` provide the audit trail for why violations were
cleared. For long-term history users are expected to forward the OTEL
event stream to their log backend.

# Drawbacks

[drawbacks]: #drawbacks

- **Punctual acknowledgements are one-shot.** A reappearing violation of the
  same executable (e.g. a process that respawns) gets a new `id` and has to
  be acknowledged again. This is intentional but means that an operator who
  wanted to permanently silence a noisy binary has to either add it to the
  allowlist or re-acknowledge after every churn. We accept this because
  per-incident triage is what the feature is for; bulk silencing belongs in
  the allowlist.
- **Annotations are consumed and not visible after processing.** If an
  operator makes a typo in the violation `id` or the annotation, the
  controller silently removes it and emits a `WARN` OTEL log. Without an
  OTEL collector configured the operator gets no feedback that the
  acknowledgement was a no-op. We mitigate this by also surfacing
  `status.acknowledgedViolations` (a missing entry for the expected
  violation is the user-visible signal) and by always emitting the OTEL log.
- **Annotation values are unbounded.** The `reason` is a free-form string
  and there is no validation. We rely on Kubernetes' 256 KiB per-object
  annotation budget to keep this from being abused.
- **`id` is per-policy, not global.** A violation id is unique within its
  `WorkloadPolicy` only. Two policies in different namespaces can both
  have a violation with `id=1`, and a violation that has been
  acknowledged or expired away can no longer be referenced. Operators
  always cite a violation as `<namespace>/<policy>:<id>` (e.g.
  `foo/my-policy:42`); the plugin renders this automatically. The
  counter itself is per-policy and survives controller restarts because
  it is persisted in `status.nextViolationID`.
- **Stale `id` race.** A violation acknowledged while the controller is
  still rebuilding `status.violations` from a fresh agent scrape could
  reference an `id` that is about to disappear. The controller handles
  this by treating unmatched `id`s as a no-op (annotation removed, WARN
  log), but the operator experience is "I acknowledged it and nothing
  happened." We accept this corner case because it is rare and
  self-recovering: the next scrape will produce a new violation with a
  new `id` to acknowledge if it is still an issue.
- **Pod name collisions on StatefulSets** can cause premature deletion: if
  a new pod with the same name comes up before the violation is
  reconciled, the old violation might persist longer than intended.
  Acknowledging by `id` rather than by name avoids the worst of this
  because the controller targets the specific record, not "all
  violations matching this pod name".

# Alternatives considered

[alternatives]: #alternatives

## Rejected: `spec.acknowledgedViolations` list

Our first accepted version of this RFC put acknowledgements in
`spec.acknowledgedViolations` as a list of `{id, reason, match}` entries.
We rejected this on second thought because:

- An acknowledgement is a triage decision, not a policy decision, so
  putting it in `spec` is conceptually wrong. It would also bump
  `observedGeneration` and trigger a rollout whenever an operator
  acknowledges something, which is wasted work.
- The operator would have to fetch the violation's `id`, then go to the
  spec, write a matching entry, and reason about ordering. Annotations
  are a more direct user interface: read `id` from status, set an
  annotation, the controller does the rest.
- The "match" fields (`podUID`, `containerName`, `executablePath`) on
  the acknowledgement entry were needed because we did not have a
  stable `id` on the violation itself. With `id` on the record the
  acknowledgement can target a single record directly, which is more
  precise and avoids the pod-UID-on-StatefulSets footgun.

The annotation form keeps the spec immutable for an acknowledgement,
gives the controller a clear one-shot signal, and keeps the durable
audit trail in `status.acknowledgedViolations`.

## Rejected: `status.acknowledgedViolations` written directly by the user

We considered letting operators push entries straight into
`status.acknowledgedViolations` (e.g. via a `kubectl patch --subresource=status`).
We rejected it because:

- Status writes should be controller-driven; opening them to operators
  invites races between the user and the controller rebuilding the
  field on the next reconcile.
- It does not give us a hook to emit the OTEL acknowledgement log,
  because the controller has no signal that something changed.
- Annotations naturally carry the one-shot semantics: the controller
  removes them, the user does not have to clean up.

## Rejected: active boolean with status recomputation

We initially designed a system where each `ViolationRecord` would carry an
`active` boolean that the controller recomputed on every reconcile. A violation
would be marked `active: false` when the pod was gone or the binary was
allowlisted. While this preserved history and avoided mutation of the
violations list, it made every violation look equally important in dashboards
and required operators to filter on `active == true` to find actionable items.
The approach also had no way for operators to explicitly acknowledge a
violation as accepted during triage, leaving no audit trail for "I know about
this and it's okay." Deletion of resolved violations, combined with the
annotation-driven acknowledgement flow, provides a cleaner signal and better
matches how security teams actually work.

## Rejected: violation liveness via image digest

We also considered a design where each `ViolationRecord` would carry the
container's resolved image **digest** (from
`.status.containerStatuses[].imageID`, never the mutable tag), captured at
the time the violation was emitted by the agent. A record would be active
if and only if both its digest matched what the container is currently
running and its `executablePath` was not in the container's allowlist. The
controller would expose a derived `activeViolationCount` and a `Compliant`
condition (`True` when the count is zero), giving monitors a single field
to read.

Clearance would be tied to the actual remediation action: rebuilding the image
invalidates every record carrying the old one in one shot, while a rollback
to the prior digest reactivates them, which is the correct security
behavior. Ordinary pod churn would not clear a violation, only a real image
change would. The `Compliant` condition would give external systems a
single-field health signal with no cross-CRD join. The failure mode is also
safe: for image-resident binaries the worst that can happen is a record
stays active longer than needed, never that it gets incorrectly marked
healthy. And intent stays in `spec` (the allowlist) while observed state
stays in `status`, which is the idiomatic Kubernetes split.

We rejected it on complexity grounds, specifically because we are still on
`v1alpha1` and the cost was not justified yet:

- The digest has to be threaded from the eBPF agent through the gRPC
  violation message into the controller, and the agent has to resolve the
  container's current digest at exec time. That is new logic close to the
  hot path.
- The controller needs the current per-container digest to compute
  liveness, which means watching pods or workloads. That is an additional
  high-churn informer and more state to keep consistent.
- "Active" becomes a three-way join in the reconcile loop: observed
  violations, current digests, and the allowlist. More logic, more failure
  surface.
- `imageID` format is runtime-dependent (`repo@sha256:...`, bare
  `sha256:...`, possible `docker-pullable://` prefixes). Naive string
  comparison breaks silently; correct handling needs a normalization
  convention agreed between agent and controller.
- Most damaging: it only covers image-resident executables. Binaries
  dropped at runtime into a writable layer or tmpfs have the lifetime of
  the pod instance, not the image. Closing that gap would require
  executable-origin detection at the agent, which does not exist today, so
  the added machinery would not on its own fully solve clearance.

We should revisit this if the simpler approach starts flapping or producing
false-healthy signals in practice, or once the agent can tell image-resident
binaries from runtime-dropped ones. At that point the two mechanisms could
be combined: digest liveness for image-resident violations, pod-instance
liveness for runtime-dropped ones, which would give correct derived
recovery across both classes and justify the complexity.

# Unresolved questions

[unresolved]: #unresolved-questions

- Should we add deduplication of violation records by (workload, container,
  executable) with a count field? Repeated attacks can produce many similar
  records, potentially causing unwanted data loss when the 100-record cap is
  hit. This is orthogonal to liveness and can be added separately.
