|              |                            |
| :----------- | :------------------------- |
| Feature Name | Network enforcer architecture |
| Start Date   | 2026-05-29                 |
| Category     | Architecture               |
| RFC PR       | https://github.com/kubewarden/network-enforcer/pull/9 |
| State        | **ACCEPTED**               |

# Summary

[summary]: #summary

`network-enforcer` is a Kubernetes operator. It watches east-west traffic between
workloads, derives an allow list from what it sees, and (when a user opts in)
projects that allow list into a network policy on a pluggable backend (upstream
`NetworkPolicy`, Calico, or Cilium). This RFC describes the components, the data
flow, the CRD, the backend contract, and the deployment topology.

# Motivation

[motivation]: #motivation

Hand-writing network policies is tedious and error-prone. Namespace owners know
what their workload does, but not which other workloads currently talk to it.
That information lives in flow records on the data plane, not in any Kubernetes
API object.

The operator bridges this gap:

1. Ingest live flow telemetry.
2. Aggregate flows per workload.
3. Materialise the result as a `NetworkPolicyProposal` CR.
4. If the owner labels a proposal as enforced, project it into a real policy
   on the configured backend.

The split between proposal and enforcement is the central design choice.
Observation is always on and has no side effects. Enforcement is a deliberate
label flip on a specific CR.

## Examples / User Stories

[examples]: #examples

- A platform engineer deploys `network-enforcer` cluster-wide and points the
  flow source (OBI agent) at its OTLP receiver. Within minutes every
  `Deployment`, `StatefulSet`, and `DaemonSet` that has carried traffic has a
  `NetworkPolicyProposal` in its namespace, populated with observed ingress
  and egress rules.
- A namespace owner runs `kubectl get npp`, reviews a proposal, then runs
  `kubectl label npp/<name> security.kubewarden.io/enforce=true`. The operator
  creates a `NetworkPolicy` (or the Calico/Cilium equivalent) owned by the
  proposal. Removing the label deletes the policy.
- A security auditor diffs the proposal spec against the generated policy and
  against `status.firstObserved` / `status.lastObserved` to reason about
  exposure.

# Detailed design

[design]: #detailed-design

## Goals

- **Observe before enforce.** Build a picture of real traffic before any packet
  is dropped.
- **Per-workload granularity.** One proposal per
  `(namespace, workload-kind, workload-name)` tuple. No cluster-wide policy.
- **Pluggable enforcement.** The same proposal projects to upstream
  `NetworkPolicy`, Calico `NetworkPolicy`, or Cilium `CiliumNetworkPolicy`
  without changes to the CRD or the reconcilers.
- **Stateless control plane.** The operator's only durable state lives in the
  Kubernetes API server (the CRs and the policies it owns). A manager restart
  loses observation buffers, not policy state.
- **Opt-in enforcement per workload.** Enforcement is gated by a label on the
  proposal. The default for a new proposal is "report only".

## Non-goals

- **Not a flow collector.** OTLP metrics come from an upstream agent (OBI). No
  eBPF probes, no pcap parsing, no node agent.
- **Not a policy editor UI.** The CRs are the contract.
- **Not a multi-cluster correlator.** One manager per cluster.
- **Not an L7 or identity-aware policy engine.** Only L3/L4 rules (peer,
  protocol, port). Cilium L7 features are not surfaced through the CRD.
  This will maybe come in the future using a full service mesh.
- **Not a flow archive.** The topology store is for live reasoning, not
  historical analytics. Pruning is by `LastSeen`.
- **Not a substitute for default-deny.** Whether the cluster runs a
  default-deny posture is a separate decision.

## End-to-end data flow

```
+----------------+         OTLP/gRPC          +--------------------------+
| Flow source    |  obi.network.flow.bytes    |   flowcollector.Receiver |
| (OBI / eBPF)   | =========================> |   (:4317 by default)     |
+----------------+                            +------------+-------------+
                                                           |
                                                Record(FlowRecord)
                                                           v
                                              +------------+-------------+
                                              |     topology.Store       |
                                              |  (in-memory, sync.RWMtx) |
                                              |  flowKey -> FlowRecord   |
                                              +-+----------------------+-+
                                                |                      |
                                  Workloads()   |                      | FlowsForWorkload()
                                                v                      v
                              +-----------------+-----+      +---------+-----------------+
                              |  TopologyScanner       |      | NetworkPolicyProposal     |
                              |  (30s tick, runnable)  |      | Reconciler                |
                              |  ensures one NPP per   |      | fills spec.{ingress,      |
                              |  observed workload     |      | egress} via               |
                              +-----------------+-----+      | fingerprint.Generate       |
                                                |             +------------+--------------+
                                                |  Create NPP              |
                                                v                          v Update spec/status
                                       +--------+--------------------------+--------+
                                       |       kube-apiserver: NetworkPolicyProposal |
                                       +--------+-------------------------+----------+
                                                                          |
                                                  label                   |  Watch (filtered
                                                  security.kubewarden.io/    |  on enforce label)
                                                  enforce=true            v
                                                              +-----------+--------------+
                                                              |  EnforcementReconciler   |
                                                              |  looks up podSelector,   |
                                                              |  asks Backend to Build,  |
                                                              |  Create/Update/Delete    |
                                                              +-----------+--------------+
                                                                          |
                                                  Backend.{Build,UpdateSpec,Empty}
                                                                          v
                                                              +-----------+--------------+
                                                              |  Pluggable Backend       |
                                                              |  (kubernetes / calico /  |
                                                              |   cilium)                |
                                                              +-----------+--------------+
                                                                          |
                                                          owns (controllerRef)
                                                                          v
                                                              +-----------+--------------+
                                                              |  Backend-specific Policy |
                                                              |  CR in kube-apiserver    |
                                                              +--------------------------+
```

From a packet to an enforced rule:

1. The data-plane agent emits an OTLP metric `obi.network.flow.bytes` with
   attributes naming the source and destination workload
   (`k8s.src.owner.{type,name}`, `k8s.src.namespace`, mirror attributes for
   the destination), the addresses, the transport, and the destination port.
2. `flowcollector.Receiver` runs as a `manager.Runnable` gRPC server on
   `--otlp-port` (default `4317`). It decodes the metric, filters on the
   target metric name, builds a `topology.FlowRecord`, and calls
   `Store.Record`.
3. `topology.Store` keys flows by `(source, dest, dstPort, protocol)` and
   merges duplicates (sum bytes, latest `LastSeen`). The store is a
   process-local map guarded by a `sync.RWMutex`. No persistence.
4. `TopologyScanner` ticks every 30s, walks `Store.Workloads()`, filters on
   `SupportedWorkloadTypes` (`Deployment`, `StatefulSet`, `DaemonSet`), and
   creates a `NetworkPolicyProposal` named `<lowercase-kind>-<name>` in the
   workload's namespace if one does not already exist. The scanner does not
   write spec contents.
5. `NetworkPolicyProposalReconciler` reads the store for flows touching the
   workload and calls `fingerprint.Generate` to collapse them into
   deduplicated `ProposedRule` lists for ingress and egress. It updates
   `spec.{ingress,egress}` and stamps `status.{firstObserved,lastObserved}`.
   It self-requeues every 30s so the spec converges as new flows arrive.
6. `EnforcementReconciler` watches NPPs with a predicate that fires on create
   and on `security.kubewarden.io/enforce` label changes. When `enforce=true`,
   it looks up the workload's pod selector from the live
   `Deployment`/`StatefulSet`/`DaemonSet`, asks the configured
   `PolicyBackend` to `Build` the backend-specific policy object, sets the
   NPP as owner reference, and either `Create`s or `UpdateSpec`+`Update`s
   it. When the label flips off (or is removed), it deletes the policy.

## Component responsibilities

### Flow receiver

- Accepts OTLP/gRPC metrics on the configured port.
- Filters to the flow metric emitted by the upstream agent; everything else
  is dropped silently.
- Translates the metric's datapoint attributes (workload identity, address,
  transport, port) into the in-memory flow record shape used by the rest of
  the system. Defaults protocol to TCP when absent, and treats flows with no
  resolved Kubernetes owner as external (handled later by the fingerprinter
  as a CIDR peer).
- Owns no state of its own; every record is pushed straight into the
  topology store.
- Lives inside the manager process and shuts down with it.

### Topology store

- In-memory, process-local view of recently observed flows, keyed by the
  source/destination/port/protocol tuple. Duplicate flows are merged so the
  store size is proportional to the number of distinct edges, not to flow
  volume.
- Exposes three things to the rest of the operator: record a flow, list the
  workloads it has seen, and list the flows touching a specific workload.
  A pruning hook is provided for time-based eviction.
- No persistence. The store is rebuilt from live telemetry on restart.

### Topology scanner

- Periodic loop that walks the workloads the store currently knows about
  and ensures a corresponding proposal CR exists for each supported workload
  kind. Only creates CRs; never modifies their spec.

### Proposal reconciler

- Reconciles each proposal by asking the store for the flows touching the
  referenced workload, handing them to the fingerprinter, and writing the
  resulting rules into the proposal's spec.
- Maintains the observation timestamps in status (first-seen sticky,
  last-seen always bumped).
- Self-requeues on a fixed cadence so the spec converges as new flows
  arrive. It does not react to individual flow arrivals; the cadence is the
  rhythm.

### Fingerprinter

- Pure function from a workload and its flows to a pair of deduplicated rule
  lists (ingress, egress).
- Buckets flows by peer. The peer is the workload identity when one was
  resolved, otherwise a CIDR derived from the observed address. Ports are
  collapsed into a sorted, deduplicated set.
- Output is deterministic, so identical inputs produce identical specs and
  the resulting writes are no-ops at the API server.

### Enforcement reconciler

- Watches proposal CRs with a predicate that only fires on create and on
  changes to the enforce label. Re-renders happen on opt-in and opt-out
  only, not on every flow observation. See
  [Unresolved Questions](#unresolved-questions) for the case where the spec
  changes while enforcement is on.
- Resolves the workload's pod selector from the live workload object.
- Delegates policy construction and the field-by-field update to the
  configured backend.
- Sets a controller reference on the rendered policy so deleting the
  proposal garbage-collects the policy.
- Records the generated policy name in status for traceability and clears it
  on un-enforce.

### Policy backend

The enforcement boundary. See the next section.

## CRD surface

One CRD: `NetworkPolicyProposal` (`npp`), namespaced, group
`security.kubewarden.io`, version `v1alpha1`.

```yaml
apiVersion: security.kubewarden.io/v1alpha1
kind: NetworkPolicyProposal
metadata:
  name: deployment-checkout
  namespace: shop
  labels:
    security.kubewarden.io/enforce: "true"   # opt-in switch
spec:
  workloadRef:
    kind: Deployment                       # Deployment | StatefulSet | DaemonSet
    name: checkout
  ingress:
    - peers:
        - workload: {kind: Deployment, name: frontend}
          namespace: shop
      ports:
        - {protocol: TCP, port: 8080}
  egress:
    - peers:
        - workload: {kind: StatefulSet, name: postgres}
          namespace: shop
      ports:
        - {protocol: TCP, port: 5432}
status:
  conditions: []
  generatedPolicyName: npp-deployment-checkout
  firstObserved: "2026-05-20T10:14:02Z"
  lastObserved:  "2026-05-29T09:01:33Z"
```

### Rationale

- **One CR per workload, not per traffic edge.** Operators reason about
  policy at the workload boundary. Edges are collapsed into peer and ports
  inside the proposal.
- **`workloadRef.kind` is constrained to `Deployment | StatefulSet | DaemonSet`.**
  These are the kinds the operator can resolve to a pod selector, and the
  kinds OBI emits owner attributes for. Pods, Jobs, and bare ReplicaSets are
  filtered out at the scanner. Short-lived workloads would produce proposal
  churn nobody can act on.
- **`PolicyPeer` carries either `workload+namespace` or `cidr`, not both.**
  This matches what the fingerprinter can derive from a single flow record:
  either a Kubernetes owner was resolved, or it was not.
- **Enforcement is a label, not a `spec.enforce` boolean.** A label is easy
  to flip with `kubectl label`, easy to query with selectors, and does not
  touch the spec the proposal reconciler rewrites every 30 seconds. A
  `spec.enforce` field would race with those writes.
- **No backend-specific fields.** Either every backend's vocabulary bleeds
  into the CRD (Calico selectors, Cilium L7 rules, etc.) or the CRD is the
  lowest common denominator. The current design picks the latter: peer,
  protocol, port, projected per backend.
- **`status.{firstObserved,lastObserved}`** are observation timestamps, not
  reconcile timestamps. They are the only durable record of when traffic was
  first seen for a workload, since the store itself is ephemeral.
- **The controller owns `spec`, not the user.** The proposal reconciler
  overwrites `spec.ingress` and `spec.egress` on every tick. Users express
  intent via the enforce label (and, later, dedicated override fields).
  Hand-edits to the rule lists will be clobbered.

## Pluggable backend contract

The interface lives in `internal/backend/backend.go`:

```go
type PolicyBackend interface {
    Name() string
    AddToScheme(s *runtime.Scheme) error
    Build(name, namespace string, podSelector map[string]string,
          proposal *securityv1alpha1.NetworkPolicyProposal) client.Object
    Empty() client.Object
    UpdateSpec(existing, desired client.Object)
}
```

### Method contract

- `Name() string`: identifier used by `--policy-backend` and in log lines.
  Must match the flag value (`"kubernetes"`, `"calico"`, `"cilium"`, ...)
  and be registered in `cmd/netenforcer/main.go`'s `newBackend` switch.
- `AddToScheme(s *runtime.Scheme) error`: register the backend's policy
  types with the manager's scheme so the client can `Get`, `Create`, and
  `Update` them. Return `nil` for backends whose types are already in
  `clientgoscheme` (e.g. upstream `NetworkPolicy`).
- `Build(name, namespace, podSelector, proposal) client.Object`: pure
  function. Given the proposal's `spec`, produce the backend-specific
  policy object. Implementations must:
  - Set `ObjectMeta.Name` to `name` and `ObjectMeta.Namespace` to
    `namespace`.
  - Translate each `ProposedRule` (peer plus ports) into the backend's
    native rule type. Map `PolicyPeer.workload` to a label or namespace
    selector. Map `PolicyPeer.cidr` to an IP block or CIDR rule.
  - Set the equivalent of `PolicyTypes` (where the backend has the
    concept) consistent with the rules produced.
  - Not set `OwnerReferences`. The reconciler does that.
- `Empty() client.Object`: return a zero-valued instance of the backend's
  policy type. Used by the reconciler for `client.Get` against the API
  server (to decide create vs. update) and for the delete path.
- `UpdateSpec(existing, desired client.Object)`: given an existing
  in-cluster object and a freshly `Build`-ed desired object, mutate
  `existing`'s spec fields to match `desired`. The reconciler then issues
  the `Update`. Implementations should only touch spec-shaped fields, not
  `ObjectMeta`, since the existing object carries the resource version,
  owner refs, and labels that the API server expects to be preserved.

### Behavioural expectations

- **Deterministic.** `Build` is called on every reconcile. Identical inputs
  must produce structurally identical outputs so `Update` is a no-op when
  nothing has changed.
- **No I/O.** Backends must not talk to the API server. The reconciler owns
  every read and every write.
- **No cross-namespace writes.** All produced objects live in `namespace`.
- **Scheme isolation.** A backend may import its CNI's API types, but those
  imports stay inside the backend's package. The rest of the codebase only
  sees `client.Object`.

### Adding a new backend

1. Create `internal/backend/<name>/<name>.go` with a `Backend` struct that
   implements `PolicyBackend`.
2. In `AddToScheme`, register the CNI's types (or return `nil` if they are
   built-in).
3. In `Build`, translate `proposal.Spec.Ingress` and `proposal.Spec.Egress`
   into the CNI's rule shape. The three existing backends cover the L3/L4
   mappings the CRD expresses today.
4. Wire it into `cmd/netenforcer/main.go`'s `newBackend` switch and add the name to the
   `--policy-backend` flag's help text.
5. No reconciler, CRD, scanner, store, or fingerprint changes are required.

## Deployment topology

- **Single Deployment, one container.** The manager binary runs the OTLP
  receiver, the topology scanner, and both reconcilers in one process.
- **State.** Two stores:
  - `topology.Store`: in-process memory, ephemeral. A restart loses observed
    flows. They refill from the OTLP stream within seconds to minutes.
  - Kubernetes API server: `NetworkPolicyProposal` CRs and backend policy
    CRs. The only durable state.
- **Leader election.** Off by default (`--leader-elect=false`). The lease ID
  is `6163c1ee.security.kubewarden.io` so multiple replicas can be enabled
  later without churning the lease. When leader election is on, only the
  leader runs controllers, but the OTLP receiver and the scanner are plain
  `manager.Runnable`s and will run on every replica regardless of leadership
  (see [Unresolved Questions](#unresolved-questions)). For now, run a single
  replica in production.
- **Scaling assumptions.** One manager per cluster. Vertical scaling is
  preferred. The store and the reconcilers are cheap relative to the OTLP
  decode path. Store size is proportional to the number of distinct
  `(src-workload, dst-workload, dst-port, protocol)` tuples, not to flow
  volume.
- **Flow-source topology.** OBI runs as a DaemonSet on every node and ships
  OTLP metrics to the manager's `--otlp-port` (default `4317`) via a
  `ClusterIP` Service. The manager is the OTLP receiver, not the exporter.
- **RBAC surface.** The manager needs:
  - Full verbs on `networkpolicyproposals` and the `status` and
    `finalizers` subresources.
  - Read on `apps/deployments`, `apps/statefulsets`, `apps/daemonsets` to
    resolve pod selectors.
  - Verbs on the configured backend's policy type (typically full verbs on
    `networking.k8s.io/networkpolicies`,
    `crd.projectcalico.org/networkpolicies`, or
    `cilium.io/ciliumnetworkpolicies`).
- **Failure modes.**
  - Loss of the OTLP stream: `LastSeen` stops advancing. Proposals stop
    being updated. Previously-enforced policies remain in place.
  - Manager crash: equivalent to a clean restart. The store rebuilds.
  - Backend API errors: surface as reconcile errors. Controller-runtime
    backs off and retries.

# Drawbacks

[drawbacks]: #drawbacks

- **Cold start.** Restarts lose the topology store. Until OBI re-emits a
  flow record for a `(src, dst, port, proto)` tuple, that tuple is invisible
  to the proposal reconciler, and the corresponding rule may temporarily
  disappear from the spec.
- **Spec churn.** New peers in observations rewrite `spec.{ingress,egress}`.
  Tooling that diffs proposals will see noise while the picture stabilises.
- **Observe-then-enforce can mint allow rules for malicious traffic.** If an
  attacker is already present when the operator is first installed, their
  flows become rules. The operator does not distinguish legitimate from
  anomalous traffic and is not a substitute for threat detection.
- **Backend lowest common denominator.** The CRD expresses only L3/L4.
- **One CR per workload scales with workload count.** Clusters with tens of
  thousands of workloads will have tens of thousands of NPPs and an equal
  number of backend policies. The reconcilers are O(workloads), not
  O(flows), but the API server load is not free.

# Alternatives

[alternatives]: #alternatives

- **Skip the CRD; create policies directly.** Rejected. Hides the
  observed-vs-enforced split, makes review impossible, and couples the
  observer to backend semantics.
- **One CR per traffic edge instead of per workload.** Rejected. Explodes
  the object count, and operators reason at the workload boundary anyway.
- **Persist the topology store.** Considered and rejected for v1. Live
  telemetry refills the store fast enough that running a database is not
  worth the operational cost.
- **Push proposals across all backends simultaneously.** Rejected. A cluster
  has one effective enforcement plane. A single `--policy-backend` flag
  matches reality and keeps the reconciler simple.
- **Make `enforce` a `spec.enforce` boolean.** Rejected. It would race with
  the proposal reconciler's spec rewrites and would require a webhook to
  defend the field.

# Unresolved questions

[unresolved]: #unresolved-questions

- **Re-render on spec change while enforced.** The enforcement reconciler's
  predicate only fires on label change. If the proposal's spec changes while
  `enforce=true`, the rendered policy is not refreshed until the label is
  toggled. Likely fix: also trigger on spec change while the label is true.
- **Leader election vs. runnables.** With `--leader-elect=true`, the OTLP
  receiver and the topology scanner still run on every replica because they
  are plain `manager.Runnable`s, not leader-gated. Open question: should the
  receiver run everywhere (sharded ingestion) with only the leader writing
  CRs, or should the whole pipeline be leader-gated?
- **Pruning policy for the store.** `Store.Prune` exists but is never
  called. Needs a tick (probably co-located with the scanner) and a TTL.
- **Garbage-collecting orphaned proposals.** The scanner only creates.
  Nothing deletes proposals whose workloads no longer exist.
- **External egress representation.** Non-Kubernetes peers become `/32`
  CIDRs today. For workloads talking to external services this produces a
  long, brittle rule list. DNS or named-set support would help, but it is
  backend-specific and not currently expressible in the CRD.
- **Webhook surface.** No validation webhook yet. Some invariants
  (`WorkloadReference.Kind` enum, peer XOR cidr) are enforced by CRD
  markers alone. Cross-field validation will eventually want a webhook.
- **Status conditions.** `NetworkPolicyProposalStatus.Conditions` is
  declared but no reconciler writes to it. Condition types (`ProposalReady`,
  `Enforced`, `BackendError`, ...) should be defined before that field
  becomes part of the public contract.
