|              |                                                         |
| :----------- | :------------------------------------------------------ |
| Feature Name | Kubernetes-Native Violation Reporting                   |
| Start Date   | 2026-02-16                                              |
| Category     | Observability                                           |
| RFC PR       | https://github.com/kubewarden/runtime-enforcer/pull/275 |
| State        | **ACCEPTED**                                            |

# Summary

[summary]: #summary

Add violation reporting paths so that policy violations are visible through
standard Kubernetes primitives (`kubectl describe`, `kubectl get`) without
requiring external observability infrastructure. Each agent buffers and
deduplicates violation records in-memory; the controller scrapes violations
from agents via the existing gRPC channel (`ScrapeViolations` RPC on port
50051 with mTLS) during its periodic status sync, merges them into
WorkloadPolicy status, and keeps the most recent 100 entries. Optionally,
agents emit OTEL events (log records with `event_name` set) to a standalone
OTEL collector Deployment over a TLS-encrypted OTLP channel.

# Motivation

[motivation]: #motivation

Today, policy violations (unauthorized process executions detected by eBPF)
are only emitted as OpenTelemetry log events to an external collector. Viewing
them requires separate infrastructure, which is a poor experience for
Kubernetes-native workflows where users expect `kubectl` to be the primary
interface.

By surfacing violations as status records:

- Users see recent violation detail via `kubectl describe workloadpolicy`.
- Users get an at-a-glance view of recent violations via the status subresource.
- No external observability stack is required for basic violation visibility.

## Examples / User Stories

[examples]: #examples

**As a cluster operator**, I want to run `kubectl describe workloadpolicy my-policy`
and see recent violations with details (executable, pod, container, node) so I
can quickly triage unauthorized process executions.

**As a platform engineer**, I want `kubectl get workloadpolicy -o yaml` to show
recent violation records so I can identify noisy policies at a glance.

**As a security team member**, I want violation telemetry forwarded to our SIEM
(via OpenTelemetry/OTLP through the existing pipeline) without disrupting current
exports, and I want violations emitted as structured OTEL events so we can drive
detections and alerts.

# Detailed design

[design]: #detailed-design

## Architecture

```
Agent (per node):
  eBPF -> EventScraper -> OTEL Event ──→ Standalone OTEL Collector Deployment (TLS on port 4317)
                       -> ViolationBuffer (in-memory dedup)
                                ↑
                    Controller scrapes via gRPC (ScrapeViolations RPC, port 50051, mTLS)
                                ↓
                       WorkloadPolicy Status.Violations (merged by controller)

OTEL Collector Deployment (per cluster):
  └─ logs pipeline   → count connector + debug exporter
                           ↓
                       metrics pipeline → deltatocumulative → prometheus exporter (:9090)
```

Agents buffer and deduplicate violations in-memory. The controller scrapes
each agent during its periodic status sync tick via the existing gRPC channel
(port 50051 with mTLS), merges the results into WorkloadPolicy status, and
trims to the most recent 100 entries.

All OTEL event telemetry is sent to a standalone OTEL collector Deployment at
`<release>-otel-collector.<namespace>.svc.cluster.local:4317` over TLS.
The collector handles routing: violation events are counted into Prometheus
metrics.

## Agent side

### ViolationBuffer (`internal/violationbuf/buffer.go`)

A thread-safe in-memory buffer that deduplicates repeated violations:

1. `Record(info ViolationInfo)` — upserts by dedup key
   `(policyName, podName, containerName, executablePath, action)`,
   incrementing a count field and updating the timestamp.
2. `Drain() []ViolationRecord` — atomically swaps the buffer, returning all
   accumulated records and leaving an empty buffer for subsequent recording.

The buffer is shared between the EventScraper (which calls `Record`) and the
gRPC server (which calls `Drain` when the controller scrapes). Event loss during
rolling update is fine by us for now.

### OTEL event pipeline (`internal/events/events.go`)

The `Init` function creates an `sdklog.LoggerProvider` with an `otlploggrpc`
exporter. The OTLP channel (port 4317) is encrypted with TLS by default;
`Init` accepts a CA certificate path for verifying the collector's certificate.

Violation records are emitted as OTEL events by calling
`Record.SetEventName("policy_violation")` before `Emit()`. This marks them
as structured events on the OTLP wire protocol (available in `otel/log`
v0.16.0+).

### EventScraper changes

The `EventScraper` gains an optional `ViolationBuffer` via a functional
option (`WithViolationBuffer`). In the monitoring channel handler, after
`emitViolationEvent()`, a `reportViolation()` call sends violation info to
the buffer for deduplication and later scraping.

The existing `WithViolationLogger` option for OTEL event emission is preserved
and now targets the standalone collector.

### Agent flags

- `--violation-otlp-endpoint`: gRPC endpoint for OTEL event reporting
  (standalone collector or third-party collector, empty = disabled).
- `--node-name`: defaults to `NODE_NAME` env var from Downward API.

## Controller side

### WorkloadPolicyStatusSync scrape flow

During each sync tick, after collecting policy status from each agent, the
controller also calls `ScrapeViolations` on each agent connection. Violations
are collected and grouped by policy namespaced name.

In `processWorkloadPolicy`, the scraped violations for that policy are
appended to `newPolicy.Status.Violations` (append to tail, trim head to
keep the most recent `MaxViolationRecords` entries). This replaces the
previous "preserve violations" hack. The violation records are ordered from
newest to oldest.

## gRPC changes

A new `ScrapeViolations` RPC is added to the existing `AgentObserver` service:

```protobuf
rpc ScrapeViolations(ScrapeViolationsRequest) returns (ScrapeViolationsResponse) {}

message ScrapeViolationsRequest {}
message ViolationRecord {
  google.protobuf.Timestamp timestamp = 1;
  string pod_name = 2;
  string container_name = 3;
  string executable_path = 4;
  string node_name = 5;
  string action = 6;
  string policy_name = 7;
  uint32 count = 8;
}
message ScrapeViolationsResponse {
  repeated ViolationRecord violations = 1;
}
```

This reuses the existing gRPC channel (port 50051 with mTLS) so no new
ports or connections are needed.

## CRD changes

A `ViolationRecord` struct captures individual violation details, and a
`ViolationStatus` struct holds the most recent records:

```go
const MaxViolationRecords = 100

type ViolationRecord struct {
    Timestamp      metav1.Time `json:"timestamp"`
    PodName        string      `json:"podName"`
    ContainerName  string      `json:"containerName"`
    ExecutablePath string      `json:"executablePath"`
    NodeName       string      `json:"nodeName"`
    Action         string      `json:"action"`
    Count          int32       `json:"count"`
}

type ViolationStatus struct {
    Violations []ViolationRecord `json:"violations,omitempty"`
}
```

## RBAC

The agent remains **read-only** on the K8s API — it does not need any
permissions on `workloadpolicies/status`. All status writes are performed
by the controller.

## OTLP encryption

The OTLP channel on port 4317 is encrypted with TLS by default.

# OTEL Collector Deployment

## Overview

An opinionated OTEL collector runs as a standalone Deployment (one replica per
cluster), enabled by default via `agent.violations.collector.enabled`. Agents
send violation events to the collector Service at
`<release>-otel-collector.<namespace>.svc.cluster.local:4317` over TLS.

A ClusterIP Service exposes:
- Port 4317 (OTLP gRPC, TLS) for receiving telemetry from agents
- Port 9090 (Prometheus) for metrics scraping

## Violation metrics

The collector uses the OTEL Collector `count` connector to derive a Prometheus
counter from violation event records:

```
runtime_enforcer_violations_total{policy_name, k8s_namespace_name, action, node_name}
```

The `deltatocumulative` processor converts the delta counters from the
`count` connector into cumulative counters suitable for Prometheus scraping.
Metrics are exposed on port 9090 via the `prometheus` exporter. The logs
pipeline also includes a `debug` exporter so that violation event records are
visible in the collector's stdout.

## Disabling the collector

Users who already have their own OTEL collector can set
`agent.violations.collector.enabled=false` and configure
`agent.violations.otlpEndpoint` to point directly at their collector. In this
mode no collector Deployment is created.

## Image

The collector uses `otel/opentelemetry-collector-contrib` because it requires
the `prometheus` exporter, `count` connector, and `deltatocumulative`
processor which are not available in the core distribution.

# Drawbacks

[drawbacks]: #drawbacks

- **Scrape latency**: violations are only visible in WP status after the
  controller's next sync tick (default 30s). This is acceptable for a
  status-based view but means violations are not real-time in `kubectl`.
  The OTEL event pipeline provides near-real-time visibility for alerting.
- **Status size**: storing up to 100 violation records in status increases the
  WP object size. The `MaxViolationRecords` cap keeps this bounded, but high
  violation rates will cause rapid turnover of records.

# Alternatives

[alternatives]: #alternatives

- **Agents patch WorkloadPolicy status directly**: each agent buffers
  violations and periodically patches `WorkloadPolicy.Status.Violations`
  using a merge patch. This was the original accepted design. It requires
  widening agent RBAC (agents need `get`/`patch` on `workloadpolicies/status`)
  and introduces concurrent-write concerns (rapid patches from many agents
  cause transient conflicts). The controller-scrape approach keeps agents
  read-only and centralizes writes.
- **Route violations through the operator via OTLP**: keeps agents read-only
  but adds a gRPC hop, requires the operator to run an OTLP receiver, and
  creates a single point of failure/bottleneck for violation reporting across
  all nodes.
- **Use Kubernetes Events for violations**: provides `kubectl describe`
  visibility and built-in dedup/TTL, but Events are ephemeral (default 1h
  TTL), not queryable via the status subresource, and add RBAC surface for
  event creation. Storing records in status provides a more durable and
  structured view.
- **Use a custom CRD for violations**: we explored two variants of this
  approach. The first was an atomic CRD where each violation produces its own
  resource (one CR per violation event). The second was a fatter, per-policy
  CRD that accumulates multiple violation records in a single resource (similar
  to what we do in status, but in a dedicated object). Both options offer
  cleaner separation of concerns, but they add significant overhead in terms of
  code: additional CRD definitions, controllers, RBAC rules, garbage
  collection logic, and generated client boilerplate. The current approach of
  storing the last 100 records directly in WorkloadPolicy status is simpler,
  covers all current use cases, and avoids the object sprawl and management
  complexity that a dedicated CRD would introduce. If future requirements
  demand longer retention or cross-policy querying, a dedicated CRD can be
  revisited.

# Unresolved questions

[unresolved]: #unresolved-questions

- Should the `ViolationStatus` include per-node or per-container breakdowns,
  or is the flat list of the last 100 records sufficient for the initial version?
- Should the OTEL collector Deployment be scaled beyond 1 replica for HA, or
  is single-replica acceptable for the initial version?
