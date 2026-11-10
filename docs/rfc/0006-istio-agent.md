|              |                                                       |
| :----------- | :---------------------------------------------------- |
| Feature Name | Pull-based event collection for the Istio provider    |
| Start Date   | 2026-11-02                                            |
| Category     | Architecture                                          |
| RFC PR       | [fill this in after opening PR]                       |
| State        | **ACCEPTED**                                          |

## Summary

Istio events reach the controller by push today: a log shipper on every node sends
ztunnel's connection log to a Service that fronts every controller replica, while only
the elected leader listens. Most shipments land on a pod that refuses them, so events are
delayed and eventually lost. We replace push with pull: an agent on every node keeps
classified events in an in-memory ring buffer, and the leader periodically drains it.
Enrichment and OTel emission remain in the controller.

This records the split of work, the best-effort delivery contract, and which side of the
hop holds the certificate. Following the [review of #640](https://github.com/kubewarden/network-enforcer/issues/640#issuecomment-6743660947),
the design uses runtime-enforcer's simple ring-buffer approach instead of durable state,
resumable cursors, or maximum-age retention.

## Context

The current path turns ztunnel connection logs into learned traffic and violations. It
has four problems; the last one has a different cause from the rest:

- The receiving Service selects every controller replica; the receiver only runs on the
  leader. The other replicas refuse the connection, and the sender retries onto another
  random pod. Loss is a matter of luck, per node, per batch.
- Every node ships to a single pod, whatever the replica count. Adding replicas does not
  add capacity, and the failure gets worse as the cluster grows.
- The failure is loss, not corruption. Avoidable routing loss makes learning and
  violation reporting less useful, even though policy enforcement remains in place.
- The shipper matches any container log whose pod name contains "ztunnel" in any
  namespace, so a tenant can write lines we would treat as learned traffic.

The cheap fixes were rejected. Electing a pod and pointing the Service at it races the
leader lease, and the window after a leader dies stays. Sending to every replica turns
dropped events into concurrent writes to the same object. Neither removes the fan-in.
Pulling also makes Istio look like the Cilium and Calico providers, which is the
consistency argument runtime-enforcer already made.

## Decision

Push is replaced by pull. A per-node agent tails ztunnel's log, classifies events, and
keeps the most recent 10,000 events in memory. The leader discovers agents, drains their
buffers, and does every Kubernetes lookup itself. There is no persisted agent event
state, cursor, or acknowledgement protocol.

### What the agent owns

Tailing, classification, a capacity-bounded ring buffer, and a scrape API with health, metrics and
graceful shutdown. It has no Kubernetes client and no service account token: it reads the
node's log directory and serves what it parsed. It runs as root with the node's log
directories mounted read-only, which puts it outside the restricted Pod Security
Standard; the chart says so rather than claiming compatibility.

### What the controller owns

Discovery, one scraper per agent, enrichment, attribution, OTel emission, and CRD status
updates. A broken agent is a per-agent problem and must never be fatal to the leader;
zero agents discovered is normal during a rollout, not an error. Enrichment stays here
because resolving peer addresses to workloads and correlating flows to policies needs
the informer caches the controller already runs, and RFC 0005 puts attribution in one
place. Replicating those caches onto every node would multiply API watch traffic to feed
a single leader. Unlike runtime-enforcer, the network-enforcer agent does not emit OTel
logs itself; the controller emits the enriched events.

Enrichment runs when an event is processed, not when it was observed, so a recycled peer
address can resolve to the workload that replaced it. There is no age limit: on a quiet
node, an event can remain buffered until the next scrape regardless of its age. This
misattribution risk is accepted rather than detected.

### Buffer and scraping

The agent reuses `internal/ringbuf`, the same Record/Drain approach used by
runtime-enforcer. The buffer holds up to 10,000 classified events. Recording into a full
buffer overwrites the oldest record; there is no maximum age or durable spool.

`ScrapeEvents` is a unary RPC with an empty request. It drains all buffered events under
a lock and returns them newest-recorded first. Records arriving after the drain belong
to the next scrape. Draining happens before the response is sent, not after delivery or
processing is confirmed. There are no event sequences, epochs, resumable cursors, or
acknowledgements. One logical consumer scrapes each agent; concurrent consumers would
split the events rather than each receive a copy.

`GetStatus` reports the number currently buffered, capacity, cumulative raw input and
overwrite counts, and the latest observed matching log paths. The counters reset when
the agent process restarts. The overwrite counter does not measure transport loss,
restart loss, or failed controller processing. There are no gap or epoch-reset counters.

The agent starts at the end of existing log files on each process start and tails new
lines without persisting offsets. No writable state volume is required. The standalone
tailer can still checkpoint offsets, but the agent does not enable that functionality.
Restart replay using a persisted read/scrape marker is a possible future improvement,
not part of this iteration.

### Delivery

Delivery is best effort. We accept losing some learning and monitoring observations;
these modes are intended for policy preparation rather than production enforcement.
Losing a violation report is more serious, but does not disable the underlying policy
protection. Consistency with runtime-enforcer and a small implementation take priority
over durable delivery for this iteration.

| Hop | Guarantee | Bound |
| --- | --- | --- |
| ztunnel log to agent buffer | best effort; new lines only, no restart replay | 10k events in memory |
| agent buffer to leader | destructive scrape, no replay after drain | all retained events per scrape |
| leader to OTel and policy status | best effort; no agent retry of drained events | controller buffers and processing |
| leader to learned proposals | idempotent rule application after receipt | bounded channel, then a queue |

Loss is possible when:

- A full agent ring buffer overwrites its oldest entries.
- An agent restarts or its pod is replaced: all buffered events are lost, and existing
  log history is skipped on startup.
- A scrape response is lost, cancelled after the drain, or rejected by transport limits:
  the drained batch is not restored. The transport must accommodate a full scrape;
  the event-count capacity is not a response-byte budget.
- The leader fails after scraping but before enriching, emitting OTel logs, or updating
  status. Its successor can scrape events still in the agent, but cannot recover the
  already-drained batch.
- Source log rotation removes unread lines, or a bounded controller queue overflows.

A successful drain will not return the same buffered record on a later scrape, but this
is not an end-to-end exactly-once or deduplication guarantee. Repeated source records and
downstream retries can still produce duplicates. Enforcement is independent of this
reporting pipeline.

### TLS

The controller is the TLS server today and already requires a client certificate from the
shipper, so that hop is mutually authenticated. The direction flip keeps the bar: the
agent becomes the server and still requires a client certificate, and the controller
becomes the client. Making mutual authentication optional would turn an authenticated hop
into an unauthenticated read of every node's flow data, including addresses, identities
and policy names; the argument that forged events cannot change enforcement covers
integrity only.

The default is a per-pod certificate issued through the CSI driver, with the pod name as
the SAN, plus a separate client identity for the controller. A shared Secret is still
supported, but one keypair mounted on every node means every agent holds the controller's
key and the certificate proves membership in the installation rather than which pod is
speaking. That mode is for installations that trust the whole namespace, and the
documentation says so. Plaintext stays for local development.

Two details follow from the flip and are easy to miss: the agent must verify the client's
identity rather than just that the certificate chains to the CA, and the controller must
rebuild its connection on every poll because credentials are captured when a connection
is created. The hop also needs a network policy admitting the agent port only from the
controller pods; nothing provides that today.

### Scale

Classification costs well under a microsecond per line on the fixtures, so the agent's
CPU is irrelevant and its real work is reading log files. The numbers that matter are
buffers. At a thousand events per second a node, the agent's 10k buffer is about ten
seconds of traffic, and the leader's violation buffer is much smaller than the sum of the
agents, so a leader-side stall becomes agent-side loss almost immediately.

That mismatch is the honest limit of this design: pulling fixes where events are lost,
not how fast one leader consumes them. Reducing the per-event lookup cost is part of the
same work, and the buffer sizes and drain cadence need a load test before anyone claims
the leader scales.

## Migration

The agent ships one release before anything uses it, because the cutover needs an upgrade
in which every node already serves:

1. **Agent only.** The agent DaemonSet is added next to the existing shipper and nobody
   reads it. No puller, no listener removal, no other change. This release is the
   barrier: it is what makes the next one safe.
2. **Cutover.** The controller starts pulling and stops listening in the same release,
   and the shipper and its receiving Service are removed with it. The agents already
   exist and are ready, so the only window is the controller rollout itself, which the
   agents can absorb up to their capacity, provided the agent processes stay alive.

A pre-upgrade check that refuses the cutover while the agent is not fully available is
the cheap guard. It has to stay quiet on a fresh install, where both components are
created together and there is no old path to protect; a check that requires the DaemonSet
to exist would otherwise block the very upgrade that creates it. If the project prefers a
single release, the equivalent is a hook that creates the agents and waits for them
before the controller rolls, and that is more machinery than the second release.

After the cutover there is no push path left, so rolling back one component without the
other leaves either a producer with no endpoint or an endpoint with no producer; roll
back both. The task breakdown for the work lives in #637 to #649.

## Consequences

The controller replica count no longer decides whether an event shipment reaches the
leader. Capacity drops are visible, and the agent remains a small in-memory component.
Restart and in-flight scrape loss are deliberately accepted; they are not made durable
or fully measurable by this design.

The costs are real. We add a second binary to build, sign and ship, running as root on
every node and listening on the network. Users who pointed their own collector at the
controller lose that integration, and users relying on a shared Secret lose per-pod
authentication. The release that introduces the agent carries a component nobody reads
yet, and an operator who skips it cannot cut over. Reports can be incomplete after a
restart, overflow, or failed scrape even while enforcement continues normally.

## Alternatives

The earlier durable-buffer design coupled events, tail offsets, sequence numbers and
acknowledgements in an atomic snapshot, with a five-minute retention limit. It offered
stronger replay guarantees but required substantially more persistence and recovery code.
That design is superseded by this RFC revision. It is not required for enforcement, and
we prefer the simpler runtime-enforcer buffer semantics.

Streaming from agent to leader was the closest alternative. It keeps the controller as the
TLS server and avoids per-pod server certificates, but it needs leader discovery and
resume after an election, and it puts the queue on the agent where the controller cannot
apply backpressure. Revisit if per-pod certificates turn out to be an operational
problem.

Fixing only the Service removes the connection lottery and leaves the fan-in, which is the
part that limits scaling.

Running ingestion on every replica would require explicit ownership of each agent:
destructive scrapes cannot independently feed multiple consumers. This would add
cross-replica coordination and is not part of this design.

Enriching on the agent would remove the leader from the read path and put the cluster-wide
indexes on every node, splitting attribution across two implementations.
