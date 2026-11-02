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
delayed and eventually lost. We replace push with pull: an agent on every node buffers
what it parses, and the leader reads from each agent at its own pace, from a cursor the
agent can honour.

This records the parts that are expensive to reverse: the split of work, the cursor,
what delivery actually means, and which side of the hop holds the certificate.

## Context

The current path turns ztunnel connection logs into learned traffic and violations. It
has four problems; the last one has a different cause from the rest:

- The receiving Service selects every controller replica; the receiver only runs on the
  leader. The other replicas refuse the connection, and the sender retries onto another
  random pod. Loss is a matter of luck, per node, per batch.
- Every node ships to a single pod, whatever the replica count. Adding replicas does not
  add capacity, and the failure gets worse as the cluster grows.
- The failure is loss, not corruption. For a product whose monitor and protect modes are
  the product, silence is the worst outcome.
- The shipper matches any container log whose pod name contains "ztunnel" in any
  namespace, so a tenant can write lines we would treat as learned traffic.

The cheap fixes were rejected. Electing a pod and pointing the Service at it races the
leader lease, and the window after a leader dies stays. Sending to every replica turns
dropped events into concurrent writes to the same object. Neither removes the fan-in.
Pulling also makes Istio look like the Cilium and Calico providers, which is the
consistency argument runtime-enforcer already made.

## Decision

Push is replaced by pull. A per-node agent tails ztunnel's log, classifies events,
buffers them briefly and serves them to the leader. The leader discovers agents, keeps a
cursor per agent, and does every Kubernetes lookup itself.

### What the agent owns

Tailing, classification, a bounded buffer, and a small read API with health, metrics and
graceful shutdown. It has no Kubernetes client and no service account token: it reads the
node's log directory and serves what it parsed. It runs as root with the node's log
directories mounted read-only, which puts it outside the restricted Pod Security
Standard; the chart says so rather than claiming compatibility.

### What the controller owns

Discovery, one puller per agent, enrichment and attribution. A broken agent is a
per-agent problem and must never be fatal to the leader; zero agents discovered is normal
during a rollout, not an error. Enrichment stays here because resolving peer addresses to
workloads and correlating flows to policies needs the informer caches the controller
already runs, and RFC 0005 puts attribution in one place. Replicating those caches onto
every node would multiply API watch traffic to feed a single leader.

The consequence is that enrichment runs when an event is processed, not when it was
observed, so a recycled peer address can resolve to the workload that replaced it. The
replay window bounds that, and inside the window the misattribution is accepted rather
than detected.

### The cursor

Every event gets a sequence number. The buffer also has an epoch: a random identifier for
the buffer instance, checkpointed with the sequence and the read position, so a container
restart continues the same sequence while a new pod starts a new one. Using the pod
identity as the epoch was rejected because a container restart keeps the pod identity and
resets the counter, which would leave the controller's cursor ahead of the agent.

Pulls are unary. Each pull carries the acknowledgement for the previous batch and returns
events after the last one acknowledged; the agent keeps the highest acknowledged sequence
so a new leader can resume from the agent instead of from its own memory. Acknowledging
at pull time was rejected: a response lost in flight, or a batch whose last event the
consumer refused, would then be skipped by the next leader, which is the silent skip this
design exists to remove.

"Acknowledged" means accepted into the leader's buffers, not written to the API. A
leader that dies in between loses what it held, and a handover looks like a death from
the agent's side. That is the exposure, and it is bounded by one leader's memory rather
than by the cluster.

If a pull asks for a cursor older than the buffer still holds, the agent reports the gap
and how much it dropped instead of pretending. Gaps, drops and epoch resets are counted
on both sides and exported per node, because a node falling behind is an operational
signal, not noise.

### Delivery

At least once, from the agent's buffer to the leader's buffers, while the buffer holds
the event. Everything above and below that is weaker, and deliberately stated:

| Hop | Guarantee | Bound |
| --- | --- | --- |
| ztunnel log to agent buffer | at least once while retained | 10k events / 5 minutes |
| agent buffer to leader buffers | at least once while retained; the leader acknowledges what it accepted | one batch per pull |
| leader buffers to policy status | best effort, duplicates suppressed by event identity | bounded buffer, periodic drain |
| leader buffers to learned proposals | idempotent, the same rule applied twice is the same rule | bounded channel, then a queue |

What that leaves out:

- A container restart loses whatever was buffered and not yet read. A new pod replays the
  current log file, which is bounded by log rotation, and loses whatever rotation already
  removed. An epoch change is the only signal for the latter.
- A leader that dies between accepting a batch and writing status loses that batch.
  Rewinding on a failed write was rejected: one policy's write conflict would replay every
  node's events, and a flapping policy would never make progress.
- A slow consumer shows up as loss. If the leader's violation buffer fills, it overwrites
  its oldest entries; the alternative is unbounded memory. Pull fixes where events are
  lost on the wire, not how fast the leader consumes them.
- Duplicates are suppressed by the identity of the observed event, not by re-deriving the
  record and comparing it: enrichment changes between a first delivery and a replay, the
  acknowledgement history is capped, and record timestamps can be rewritten. That
  suppression lives in the leader's memory and is lost with it.
- A durable on-disk spool would remove the first caveat, and only that one. The
  leader-crash caveat needs durable staging before acknowledgement, which is the same
  project as persisting observations, not a change to the agent. Both are out of scope
  for this iteration, and the table is the promise until that changes.

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
   agents cover.

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

The good part is that loss stops being random: a node that falls behind is visible, and a
controller replica count no longer decides whether events arrive.

The costs are real. We add a second binary to build, sign and ship, running as root on
every node and listening on the network. Users who pointed their own collector at the
controller lose that integration, and users relying on a shared Secret lose per-pod
authentication. The release that introduces the agent carries a component nobody reads
yet, and an operator who skips it cannot cut over. And the delivery guarantee becomes a
sentence with exceptions, which is worse than the sentence people would like to read.

## Alternatives

Streaming from agent to leader was the closest alternative. It keeps the controller as the
TLS server and avoids per-pod server certificates, but it needs leader discovery and
resume after an election, and it puts the queue on the agent where the controller cannot
apply backpressure. Revisit if per-pod certificates turn out to be an operational
problem.

Fixing only the Service removes the connection lottery and leaves the fan-in, which is the
part that limits scaling.

Running ingestion on every replica with leader-bound writes is possible later on the same
cursor design if the leader is still the ceiling. It reintroduces cross-replica
coordination, so it is not the first move.

Enriching on the agent would remove the leader from the read path and put the cluster-wide
indexes on every node, splitting attribution across two implementations.
